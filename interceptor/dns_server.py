"""Local DNS server that intercepts all lookups and checks with the scorer."""

import asyncio
import json
import socket
import struct
import threading

import httpx
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

import config
from data.whitelist import is_whitelisted
from interceptor.cache import get_cached_score, set_cached_score, log_event, init_db
from utils.logger import setup_logger

log = setup_logger("dns_server")

# Internal domains / record types we always forward without scanning
_SKIP_QTYPES = {QTYPE.AAAA, QTYPE.SRV, QTYPE.MX, QTYPE.TXT, QTYPE.PTR, QTYPE.SOA, QTYPE.NS}


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


async def _score_domain(domain: str) -> dict:
    """Call the FastAPI scorer and return {score, verdict, reasons}."""
    url = f"http://{config.SCORER_HOST}:{config.SCORER_PORT}/scan"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json={"url": domain})
        resp.raise_for_status()
        return resp.json()


def _build_block_response(request: DNSRecord) -> bytes:
    """Build a DNS response pointing to our local block-page server."""
    reply = request.reply()
    qname = request.q.qname
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(config.BLOCK_PAGE_HOST), ttl=60))
    return reply.pack()


class DNSHandler:
    """Handles a single DNS query."""

    def __init__(self, data: bytes, addr: tuple, transport: socket.socket, loop: asyncio.AbstractEventLoop):
        self.data = data
        self.addr = addr
        self.transport = transport
        self.loop = loop

    async def handle(self):
        try:
            request = DNSRecord.parse(self.data)
        except Exception:
            return

        qname = str(request.q.qname).rstrip(".")
        qtype = request.q.qtype

        # Skip non-A queries (AAAA, MX, etc.) — just forward them
        if qtype in _SKIP_QTYPES:
            resp = await asyncio.to_thread(_forward_dns, self.data)
            self.transport.sendto(resp, self.addr)
            return

        # Skip local / internal domains
        if qname.endswith(".local") or qname == "localhost":
            resp = await asyncio.to_thread(_forward_dns, self.data)
            self.transport.sendto(resp, self.addr)
            return

        # ── Tier 1: Whitelist ──
        if is_whitelisted(qname):
            log.info(f"ALLOW (whitelist)  {qname}")
            resp = await asyncio.to_thread(_forward_dns, self.data)
            self.transport.sendto(resp, self.addr)
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
                self.transport.sendto(resp, self.addr)
                await log_event(qname, score, "block_cached")
            else:
                log.info(f"ALLOW (cached {score:.2f})  {qname}")
                resp = await asyncio.to_thread(_forward_dns, self.data)
                self.transport.sendto(resp, self.addr)
                await log_event(qname, score, "allow_cached")
            return

        # ── Tier 3: Score via API ──
        log.info(f"SCORING ...        {qname}")
        try:
            result = await _score_domain(qname)
            score = result["score"]
            verdict = result["verdict"]
            reasons = json.dumps(result.get("reasons", []))

            # Cache the result
            await set_cached_score(qname, score, reasons, verdict)

            if verdict == "block":
                log.warning(f"BLOCK ({score:.2f})       {qname}  reasons={result.get('reasons', [])}")
                resp = _build_block_response(request)
                self.transport.sendto(resp, self.addr)
                await log_event(qname, score, "block")
            else:
                log.info(f"ALLOW ({score:.2f})       {qname}")
                resp = await asyncio.to_thread(_forward_dns, self.data)
                self.transport.sendto(resp, self.addr)
                await log_event(qname, score, "allow")

        except Exception as e:
            # Failsafe: if scorer is down, ALLOW the request (don't break internet)
            log.error(f"ALLOW (scorer error: {e})  {qname}")
            resp = await asyncio.to_thread(_forward_dns, self.data)
            self.transport.sendto(resp, self.addr)
            await log_event(qname, None, "allow_error")


class AsyncDNSServer:
    """UDP DNS server running in an asyncio event loop."""

    def __init__(self, host: str = config.DNS_LISTEN_HOST, port: int = config.DNS_LISTEN_PORT):
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._running = False

    async def start(self):
        await init_db()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.setblocking(False)
        self._running = True
        log.info(f"DNS server listening on {self.host}:{self.port}")

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await asyncio.to_thread(self._recv)
                if data:
                    handler = DNSHandler(data, addr, self._sock, loop)
                    asyncio.create_task(handler.handle())
            except OSError:
                if self._running:
                    raise
                break

    def _recv(self) -> tuple[bytes | None, tuple | None]:
        import select
        ready, _, _ = select.select([self._sock], [], [], 0.5)
        if ready:
            return self._sock.recvfrom(4096)
        return None, None

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None
        log.info("DNS server stopped")
