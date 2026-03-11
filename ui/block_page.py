"""Local HTTP server that serves the block/warning page.

Listens on port 80 so blocked domains (DNS → 127.0.0.1) show the warning
instead of a browser connection error.
"""

import asyncio
from pathlib import Path

from utils.logger import setup_logger
import config

log = setup_logger("block_page")

WARNING_HTML = (Path(__file__).parent / "warning.html").read_text(encoding="utf-8")


async def handle_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle an incoming HTTP request — extract Host header and serve block page."""
    try:
        # Read the request line
        request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)

        # Read headers to extract Host (the blocked domain)
        host_domain = "suspicious domain"
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if line in (b"\r\n", b"\n", b""):
                break
            header = line.decode("utf-8", errors="ignore").strip()
            if header.lower().startswith("host:"):
                host_domain = header.split(":", 1)[1].strip()

        # Inject the blocked domain into the HTML
        html = WARNING_HTML.replace(
            "document.getElementById('blocked-domain').textContent = 'Suspicious domain blocked';",
            f"document.getElementById('blocked-domain').textContent = '{host_domain}';",
        )

        body = html.encode("utf-8")
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"Cache-Control: no-store\r\n"
            f"\r\n"
        ).encode("utf-8") + body

        writer.write(response)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def start_block_page_server(
    host: str = config.BLOCK_PAGE_HOST,
    port: int = config.BLOCK_PAGE_PORT,
):
    server = await asyncio.start_server(handle_request, host, port)
    log.info(f"Block page server on http://{host}:{port}")
    async with server:
        await server.serve_forever()
