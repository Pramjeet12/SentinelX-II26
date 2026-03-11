"""Windows DNS configuration — redirect system DNS to our local server and restore on exit."""

import subprocess
import ctypes
import sys

from utils.logger import setup_logger

log = setup_logger("dns_config")


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin_restart():
    """Re-launch the current script with admin privileges via UAC."""
    if is_admin():
        return True
    log.warning("Requesting admin privileges (UAC prompt)...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)


def _get_active_interface() -> str:
    """Find the active network interface name."""
    result = subprocess.run(
        ["netsh", "interface", "ip", "show", "config"],
        capture_output=True, text=True, check=True,
    )
    # Parse the output to find the first interface with a default gateway
    current_iface = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if line and not line[0].isspace() and stripped.startswith("Configuration for interface"):
            # Extract interface name between quotes
            current_iface = stripped.split('"')[1] if '"' in stripped else None
        if current_iface and "Default Gateway" in stripped:
            gateway = stripped.split(":")[-1].strip()
            if gateway and gateway != "None":
                return current_iface
    # Fallback
    return "Wi-Fi"


def _get_current_dns(interface: str) -> list[str]:
    """Get current DNS servers for an interface."""
    result = subprocess.run(
        ["netsh", "interface", "ip", "show", "dns", interface],
        capture_output=True, text=True,
    )
    servers = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        # Lines with DNS IPs look like: "1.1.1.1" or "Statically Configured DNS Servers:    1.1.1.1"
        parts = stripped.split()
        for part in parts:
            octets = part.split(".")
            if len(octets) == 4:
                try:
                    if all(0 <= int(o) <= 255 for o in octets):
                        servers.append(part)
                except ValueError:
                    continue
    return servers


class DNSRedirector:
    """Manages Windows DNS settings — redirect to local and restore."""

    def __init__(self):
        self.interface: str | None = None
        self.original_dns: list[str] = []
        self._active = False

    def activate(self):
        """Point Windows DNS to 127.0.0.1 (our local DNS server)."""
        if not is_admin():
            log.error("Cannot change DNS without admin privileges!")
            return False

        self.interface = _get_active_interface()
        self.original_dns = _get_current_dns(self.interface)
        log.info(f"Interface: {self.interface}")
        log.info(f"Original DNS: {self.original_dns}")

        # Set primary DNS to our local server
        subprocess.run(
            ["netsh", "interface", "ip", "set", "dns",
             self.interface, "static", "127.0.0.1", "primary"],
            capture_output=True, check=True,
        )
        log.info("DNS redirected to 127.0.0.1 ✓")

        # Flush DNS cache so Windows uses our server immediately
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)

        self._active = True
        return True

    def restore(self):
        """Restore original DNS settings."""
        if not self._active or not self.interface:
            return

        try:
            if self.original_dns:
                # Restore first DNS server
                subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns",
                     self.interface, "static", self.original_dns[0], "primary"],
                    capture_output=True, check=True,
                )
                # Add additional DNS servers
                for dns in self.original_dns[1:]:
                    subprocess.run(
                        ["netsh", "interface", "ip", "add", "dns",
                         self.interface, dns, "index=2"],
                        capture_output=True,
                    )
            else:
                # Was originally DHCP
                subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns",
                     self.interface, "dhcp"],
                    capture_output=True, check=True,
                )

            subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
            log.info(f"DNS restored to {self.original_dns or 'DHCP'} ✓")
        except Exception as e:
            log.error(f"Failed to restore DNS: {e}")
        finally:
            self._active = False
