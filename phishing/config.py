"""Central configuration for SentinelX."""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Paths ──
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "sentinelx.db"

# ── OpenAI ──
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o-mini"  # cheap + fast, good enough for URL scoring

# ── Scoring thresholds ──
BLOCK_THRESHOLD = 0.7    # score > 0.7 → block
ALLOW_THRESHOLD = 0.3    # score < 0.3 → allow (skip further checks)

# ── DNS Server ──
DNS_LISTEN_HOST = "127.0.0.1"
DNS_LISTEN_PORT = 53
UPSTREAM_DNS = "8.8.8.8"      # Google DNS — fallback / forwarding
UPSTREAM_DNS_PORT = 53

# ── FastAPI Scorer ──
SCORER_HOST = "127.0.0.1"
SCORER_PORT = 8000

# ── Block Page Server ──
BLOCK_PAGE_HOST = "127.0.0.1"
BLOCK_PAGE_PORT = 80  # Must be 80 — browsers default to port 80 for HTTP

# ── Cache TTL ──
CACHE_TTL_SECONDS = 86400  # 24 hours — re-score after this
