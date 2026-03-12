"""Windows toast notifications for blocked phishing links.

Uses PowerShell balloon tips — works reliably from elevated (admin) processes
unlike winotify which fails silently when run as admin.
"""

import subprocess
import threading

from utils.logger import setup_logger

log = setup_logger("notify")


def notify_block(domain: str, reasons: list[str] | None = None):
    """Show a Windows balloon notification when a phishing link is blocked."""
    log.debug(f"notify_block called: domain={domain}, reasons={reasons}")
    threading.Thread(target=_show_balloon, args=(domain, reasons), daemon=True).start()


def _show_balloon(domain: str, reasons: list[str] | None):
    try:
        reason_text = reasons[0] if reasons else "Suspicious domain detected"
        # Escape single quotes for PowerShell
        safe_domain = domain.replace("'", "''")
        safe_reason = reason_text.replace("'", "''")

        ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
$icon = New-Object System.Windows.Forms.NotifyIcon
$icon.Icon = [System.Drawing.SystemIcons]::Shield
$icon.BalloonTipIcon = 'Warning'
$icon.BalloonTipTitle = 'SentinelX - Link Blocked'
$icon.BalloonTipText = '{safe_domain} - {safe_reason}'
$icon.Visible = $true
$icon.ShowBalloonTip(5000)
Start-Sleep -Seconds 6
$icon.Dispose()
"""
        log.debug(f"Launching PowerShell balloon for: {domain}")
        proc = subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode == 0:
            log.info(f"Toast SUCCESS for: {domain}")
        else:
            log.error(f"Toast FAILED for: {domain} | exit={proc.returncode} | stderr={proc.stderr.strip()}")
        if proc.stdout.strip():
            log.debug(f"Toast stdout: {proc.stdout.strip()}")
    except subprocess.TimeoutExpired:
        log.error(f"Toast TIMEOUT for: {domain} (PowerShell took >15s)")
    except Exception as e:
        log.error(f"Toast EXCEPTION for: {domain} | {type(e).__name__}: {e}")
