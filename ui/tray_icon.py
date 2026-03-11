"""System tray icon for SentinelX using pystray."""

import threading

from PIL import Image, ImageDraw
import pystray

from utils.logger import setup_logger

log = setup_logger("tray")


def _create_icon_image(color: str = "#2563eb") -> Image.Image:
    """Generate a simple shield icon programmatically."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Shield shape — simple rounded rect with pointed bottom
    draw.rounded_rectangle([8, 6, 56, 44], radius=8, fill=color)
    draw.polygon([(8, 40), (32, 60), (56, 40)], fill=color)
    # "S" letter in white
    draw.text((22, 14), "S", fill="white")
    return img


class TrayIcon:
    """System tray icon with start/stop/exit controls."""

    def __init__(self, on_stop_callback=None):
        self._on_stop = on_stop_callback
        self._icon: pystray.Icon | None = None

    def _build_menu(self):
        return pystray.Menu(
            pystray.MenuItem("SentinelX — Active", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Stop & Restore DNS", self._on_stop_click),
            pystray.MenuItem("Exit", self._on_exit_click),
        )

    def _on_stop_click(self, icon, item):
        log.info("User requested stop via tray")
        if self._on_stop:
            self._on_stop()

    def _on_exit_click(self, icon, item):
        log.info("User requested exit via tray")
        if self._on_stop:
            self._on_stop()
        if self._icon:
            self._icon.stop()

    def run(self):
        """Run the tray icon (blocking — call from a thread)."""
        self._icon = pystray.Icon(
            name="SentinelX",
            icon=_create_icon_image(),
            title="SentinelX — Phishing Interceptor (Active)",
            menu=self._build_menu(),
        )
        self._icon.run()

    def stop(self):
        if self._icon:
            self._icon.stop()

    def run_in_thread(self) -> threading.Thread:
        """Start the tray icon in a background thread and return the thread."""
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        return t
