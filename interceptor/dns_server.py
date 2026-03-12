"""Local DNS server that intercepts all lookups and checks with the scorer."""

import asyncio
import json
import socket

import httpx
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, RCODE

import config
from data.whitelist import is_whitelisted
from interceptor.cache import get_cached_score, set_cached_score, log_event, init_db
from ui.notify import notify_block
from utils.logger import setup_logger

log = setup_logger("dns_server")

# Internal domains / record types we always forward without scanning
_SKIP_QTYPES = {QTYPE.AAAA, QTYPE.SRV, QTYPE.MX, QTYPE.TXT, QTYPE.PTR, QTYPE.SOA, QTYPE.NS}

# How long the DNS handler waits for LLM scoring before blocking by default.
# Browsers typically give up after 5s, so we must respond well before that.
_SCORE_TIMEOUT = 4.0

# Tracks domains currently being scored to avoid duplicate OpenAI calls
_pending_scores: dict[str, asyncio.Future] = {}


def _forward_dns(raw_data: bytes) -> bytes:
    """Forward a raw DNS query to the upstream DNS and return the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(raw_data, (config.UPSTREAM_DNS, config.UPSTREAM_DNS_PORT))
        resp, _ = sock.recvfrom(4096)
        return resp
    finally:
        sock.close()


async def _safe_forward_dns(raw_data: bytes) -> bytes | None:
    """Forward DNS with error handling. Returns None on failure."""
    try:
        return await asyncio.to_thread(_forward_dns, raw_data)
    except Exception as e:
        log.error(f"Upstream DNS forward failed: {e}")
        return None


async def _score_domain(domain: str) -> dict:
    """Call the FastAPI scorer and return {score, verdict, reasons}."""
    url = f"http://{config.SCORER_HOST}:{config.SCORER_PORT}/scan"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json={"url": domain})
        resp.raise_for_status()
        return resp.json()


async def _score_domain_deduped(domain: str) -> dict:
    """Score a domain, deduplicating concurrent requests for the same domain.

    If another coroutine is already scoring this domain, wait for its result
    instead of making a duplicate OpenAI API call.
    """
    if domain in _pending_scores:
        log.debug(f"Waiting on existing score request for {domain}")
        return await _pending_scores[domain]

    future: asyncio.Future = asyncio.get_event_loop().create_future()
    _pending_scores[domain] = future
    try:
        result = await _score_domain(domain)
        future.set_result(result)
        return result
    except Exception as e:
        future.set_exception(e)
        raise
    finally:
        _pending_scores.pop(domain, None)


async def _background_score(domain: str):
    """Score a domain in the background and cache the result.

    Called when the DNS handler timed out waiting for LLM scoring.
    The next DNS query for this domain will use the cached result.
    """
    try:
        result = await _score_domain_deduped(domain)
        score = result["score"]
        verdict = result["verdict"]
        reasons = json.dumps(result.get("reasons", []))
        await set_cached_score(domain, score, reasons, verdict)
        log.info(f"Background score done: {domain} → {verdict} ({score:.2f})")
    except Exception as e:
        log.error(f"Background scoring failed for {domain}: {e}")


def _build_block_response(request: DNSRecord) -> bytes:
    """Build a DNS response pointing to our local block-page server."""
    reply = request.reply()
    qname = request.q.qname
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(config.BLOCK_PAGE_HOST), ttl=60))
    return reply.pack()


def _build_servfail_response(request: DNSRecord) -> bytes:
    """Build a SERVFAIL response for when upstream DNS is unreachable."""
    reply = request.reply()
    reply.header.rcode = RCODE.SERVFAIL
    return reply.pack()


class _DNSProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that dispatches DNS queries to DNSHandler."""

    def __init__(self):
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple):
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return

        qname = str(request.q.qname).rstrip(".")
        qtype = request.q.qtype

        # Skip non-A queries (AAAA, MX, etc.) — just forward them
        if qtype in _SKIP_QTYPES:
            resp = await _safe_forward_dns(data)
            if resp:
                self.transport.sendto(resp, addr)
            else:
                self.transport.sendto(_build_servfail_response(request), addr)
            return

        # Skip local / internal domains
        if qname.endswith(".local") or qname == "localhost":
            resp = await _safe_forward_dns(data)
            if resp:
                self.transport.sendto(resp, addr)
            else:
                self.transport.sendto(_build_servfail_response(request), addr)
            return

        # ── Tier 1: Whitelist ──
        if is_whitelisted(qname):
            log.info(f"ALLOW (whitelist)  {qname}")
            resp = await _safe_forward_dns(data)
            if resp:
                self.transport.sendto(resp, addr)
            else:
                self.transport.sendto(_build_servfail_response(request), addr)
            await log_event(qname, 0.0, "allow_whitelist")
            return

        # ── Tier 2: Cache ──
        cached = await get_cached_score(qname)
        if cached:
            verdict = cached["verdict"]
            score = cached["score"]
            if verdict == "block":
                log.warning(f"BLOCK (cached {score:.2f})  {qname}")
                resp = _build_block_response(request)
                self.transport.sendto(resp, addr)
                notify_block(qname)
                await log_event(qname, score, "block_cached")
            else:
                log.info(f"ALLOW (cached {score:.2f})  {qname}")
                resp = await _safe_forward_dns(data)
                if resp:
                    self.transport.sendto(resp, addr)
                else:
                    self.transport.sendto(_build_servfail_response(request), addr)
                await log_event(qname, score, "allow_cached")
            return

        # ── Tier 3: Score via API (with timeout protection) ──
        # Browsers timeout DNS after ~5s, so we MUST respond within 4s.
        # If the LLM is still thinking, we BLOCK by default (safer than allowing
        # a phishing link through) and continue scoring in the background.
        log.info(f"SCORING ...        {qname}")
        try:
            result = await asyncio.wait_for(
                _score_domain_deduped(qname), timeout=_SCORE_TIMEOUT
            )
            score = result["score"]
            verdict = result["verdict"]
            reasons = json.dumps(result.get("reasons", []))

            # Cache the result
            await set_cached_score(qname, score, reasons, verdict)

            if verdict == "block":
                log.warning(f"BLOCK ({score:.2f})       {qname}  reasons={result.get('reasons', [])}")
                resp = _build_block_response(request)
                self.transport.sendto(resp, addr)
                notify_block(qname, result.get('reasons', []))
                await log_event(qname, score, "block")
            else:
                log.info(f"ALLOW ({score:.2f})       {qname}")
                resp = await _safe_forward_dns(data)
                if resp:
                    self.transport.sendto(resp, addr)
                else:
                    self.transport.sendto(_build_servfail_response(request), addr)
                await log_event(qname, score, "allow")

        except asyncio.TimeoutError:
            # LLM took too long — BLOCK now, score in background for next time
            log.warning(f"BLOCK (score timeout >{_SCORE_TIMEOUT}s)  {qname}")
            resp = _build_block_response(request)
            self.transport.sendto(resp, addr)
            notify_block(qname, ["Scoring timeout — blocked as precaution"])
            await log_event(qname, None, "block_timeout")
            # Continue scoring in background so next query uses the real result
            asyncio.ensure_future(_background_score(qname))

        except Exception as e:
            # Failsafe: if scorer is completely down, ALLOW (don't break internet)
            log.error(f"ALLOW (scorer error: {e})  {qname}")
            resp = await _safe_forward_dns(data)
            if resp:
                self.transport.sendto(resp, addr)
            else:
                self.transport.sendto(_build_servfail_response(request), addr)
            await log_event(qname, None, "allow_error")


class AsyncDNSServer:
    """UDP DNS server using asyncio's native datagram protocol."""

    def __init__(self, host: str = config.DNS_LISTEN_HOST, port: int = config.DNS_LISTEN_PORT):
        self.host = host
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _DNSProtocol | None = None

    async def start(self):
        await init_db()
        loop = asyncio.get_event_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            _DNSProtocol, local_addr=(self.host, self.port)
        )
        log.info(f"DNS server listening on {self.host}:{self.port}")
        # Keep running until stopped
        while self._transport is not None and not self._transport.is_closing():
            await asyncio.sleep(1)

    def stop(self):
        if self._transport:
            self._transport.close()
            self._transport = None
        log.info("DNS server stopped")
