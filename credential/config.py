"""Central configuration for Credential Leak Monitor."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

# ── Paths ──
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "credleak.db"

# ── Organization ──
ORG_DOMAIN = "acmecorp.com"  # The email domain we're monitoring
ORG_NAME = "AcmeCorp"

# ── Scan Schedule ──
SCAN_SCHEDULE_TIME = "08:00"   # Daily at this time (HH:MM)
SCAN_INTERVAL_HOURS = 24       # Or scan every N hours
SCAN_ON_STARTUP = True         # Run a scan immediately on launch

# ── SMTP Email Alerts ──
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_FROM = SMTP_USER
ALERT_TO = [SMTP_USER]  # Security team email(s)

# ── Scanner Toggles ──
ENABLE_BREACH_SCAN = True       # Check emails against breach DB
ENABLE_PASSWORD_SCAN = True     # k-Anonymity password check
ENABLE_GITHUB_SCAN = True       # Search for leaked creds in code repos
ENABLE_PASTE_SCAN = True        # Search paste sites

# ── GitHub (prototype uses local DB simulation) ──
GITHUB_KEYWORDS = ["password", "secret", "api_key", "token", "credential"]

# ── Severity Levels ──
SEVERITY_CRITICAL = "CRITICAL"  # Password found in breach (plaintext match)
SEVERITY_HIGH = "HIGH"          # Email found in major breach
SEVERITY_MEDIUM = "MEDIUM"      # Email found in minor breach / paste site
SEVERITY_LOW = "LOW"            # Mention found but no credentials
