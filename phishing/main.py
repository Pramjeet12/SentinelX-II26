"""
SentinelX — Phishing Link Interceptor
Main entry point: launches all components.
"""

import asyncio
import atexit
import signal
import sys
import threading
import uvicorn

import config
from interceptor.dns_config import DNSRedirector, is_admin, request_admin_restart
from interceptor.dns_server import AsyncDNSServer
from ui.block_page import start_block_page_server
from ui.tray_icon import TrayIcon
from utils.logger import setup_logger

log = setup_logger("main")

# ── Global state ──
dns_redirector = DNSRedirector()
dns_server = AsyncDNSServer()
shutdown_event = threading.Event()  # threading.Event — safe across threads + asyncio


def cleanup():
    """Restore DNS settings on exit — CRITICAL."""
    log.info("Cleaning up...")
    dns_server.stop()
    dns_redirector.restore()
    log.info("Shutdown complete.")


def signal_handler(sig, frame):
    log.info(f"Signal {sig} received, shutting down...")
    shutdown_event.set()


def run_fastapi_server():
    """Run the FastAPI scorer in a background thread."""
    uvicorn.run(
        "scorer.server:app",
        host=config.SCORER_HOST,
        port=config.SCORER_PORT,
        log_level="warning",
    )


async def async_main():
    """Start DNS server and block page server concurrently."""
    await asyncio.gather(
        dns_server.start(),
        start_block_page_server(),
    )


def main():
    log.info("=" * 50)
    log.info("  SentinelX — Phishing Link Interceptor")
    log.info("=" * 50)

    # ── Step 0: Admin check ──
    if not is_admin():
        log.warning("Admin privileges required to change DNS settings.")
        request_admin_restart()
        return  # Won't reach here — request_admin_restart calls sys.exit

    # ── Step 1: Register cleanup ──
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ── Step 2: Start FastAPI scorer in background thread ──
    log.info(f"Starting scorer API on {config.SCORER_HOST}:{config.SCORER_PORT}...")
    api_thread = threading.Thread(target=run_fastapi_server, daemon=True)
    api_thread.start()

    # ── Step 3: Redirect DNS ──
    log.info("Redirecting Windows DNS to local server...")
    if not dns_redirector.activate():
        log.error("Failed to redirect DNS. Exiting.")
        return

    # ── Step 4: Start tray icon ──
    tray = TrayIcon(on_stop_callback=lambda: shutdown_event.set())
    tray.run_in_thread()
    log.info("System tray icon active")

    # ── Step 5: Run DNS server + block page ──
    log.info("Starting DNS interceptor & block page server...")
    log.info("SentinelX is ACTIVE — all DNS queries are now being intercepted")
    log.info("-" * 50)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # Run async servers with a shutdown watcher
        async def run_with_shutdown():
            servers_task = asyncio.create_task(async_main())
            # Poll the threading event periodically
            while not shutdown_event.is_set():
                await asyncio.sleep(0.5)
            dns_server.stop()
            servers_task.cancel()

        loop.run_until_complete(run_with_shutdown())
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt received")
    finally:
        cleanup()
        tray.stop()
        loop.close()


if __name__ == "__main__":
    main()
