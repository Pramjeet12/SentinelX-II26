# SentinelX — Phishing Link Interceptor

A DNS-level phishing link interceptor for Windows that catches malicious URLs **from any application** — browser, PDF reader, WhatsApp, Outlook, or any app — before the connection ever reaches the internet.

---

## How It Works

```mermaid
flowchart TD
    A[👤 User clicks a link<br><i>from any app — browser, PDF, email, chat</i>] --> B[🖥️ Windows needs the IP address<br><b>DNS Query</b>: What is the IP of evil.xyz?]
    B --> C{🛡️ SentinelX DNS Server<br><b>127.0.0.1:53</b>}

    C --> D{Tier 1: Whitelist Check}
    D -->|✅ Known safe domain<br>google.com, github.com| E[Forward to real DNS<br>8.8.8.8]
    E --> F[🌐 User reaches the website normally]

    D -->|❓ Not whitelisted| G{Tier 2: Cache Check}
    G -->|🗄️ Score cached in SQLite| H{Cached verdict?}
    H -->|score ≤ 0.7| F
    H -->|score > 0.7| I[🚫 Return 127.0.0.1<br>+ Toast Notification]
    I --> J[🛑 Block page shown<br>Phishing server NEVER contacted]

    G -->|🆕 Never seen before| K[Tier 3: Score via OpenAI API]
    K --> L[FastAPI Server<br>127.0.0.1:8000/scan]
    L --> M[OpenAI LLM analyzes URL<br>Returns score 0.0 → 1.0]
    M --> N{Score result?}
    N -->|score ≤ 0.7 — Safe| O[Cache result + Forward DNS]
    O --> F
    N -->|score > 0.7 — Phishing| P[Cache result + Block DNS]
    P --> I

    style A fill:#e8f4fd,stroke:#2196F3
    style C fill:#fff3e0,stroke:#FF9800
    style F fill:#e8f5e9,stroke:#4CAF50
    style I fill:#ffebee,stroke:#f44336
    style J fill:#ffebee,stroke:#f44336
```

---

## Scoring Flow — Example

```mermaid
sequenceDiagram
    participant User
    participant App as Any App (Browser/PDF/Email)
    participant DNS as SentinelX DNS<br>127.0.0.1:53
    participant API as FastAPI Scorer<br>127.0.0.1:8000
    participant LLM as OpenAI API
    participant Block as Block Page<br>127.0.0.1:80

    Note over User,Block: Example 1: Safe link — google.com
    User->>App: Clicks https://google.com
    App->>DNS: DNS Query: google.com
    DNS->>DNS: Whitelist check ✅
    DNS->>App: Real IP: 142.251.43.142
    App->>User: Page loads normally

    Note over User,Block: Example 2: Phishing link — paypa1-secure-login.xyz
    User->>App: Clicks http://paypa1-secure-login.xyz/verify
    App->>DNS: DNS Query: paypa1-secure-login.xyz
    DNS->>DNS: Not whitelisted, not cached
    DNS->>API: POST /scan {url: "paypa1-secure-login.xyz"}
    API->>LLM: Analyze URL for phishing signals
    LLM->>API: {score: 0.85, reasons: ["PayPal lookalike", ".xyz TLD"]}
    API->>DNS: {verdict: "block", score: 0.85}
    DNS->>DNS: Cache result in SQLite
    DNS->>App: IP: 127.0.0.1 (blocked!)
    DNS-->>User: 🔔 Toast: "SentinelX — Link Blocked"
    App->>Block: HTTP GET (goes to local block page)
    Block->>User: ⚠️ Warning HTML page shown

    Note over User,Block: Phishing server was NEVER contacted
```

---

## Example: What the User Sees

### Safe Link (google.com)
```
Terminal log:
[02:32:53] INFO  dns_server  | ALLOW (whitelist)  google.com

→ Browser loads Google normally. Zero delay.
```

### Phishing Link (arnazon-security.ml)
```
Terminal log:
[02:33:00] WARNING dns_server | BLOCK (cached 0.80)  arnazon-security.ml
[02:33:00] INFO    notify     | Toast SUCCESS for: arnazon-security.ml

→ Browser shows block page (HTTP) or connection error (HTTPS)
→ Windows toast notification pops up
→ Phishing server NEVER receives any traffic
```

---

## Architecture

```mermaid
graph LR
    subgraph SentinelX [SentinelX Process]
        DNS[DNS Server<br>dnslib<br>:53]
        API[FastAPI Scorer<br>uvicorn<br>:8000]
        BP[Block Page<br>asyncio HTTP<br>:80]
        TRAY[System Tray<br>pystray]
        DB[(SQLite<br>Cache + Logs)]
        NOTIFY[Toast<br>Notifications]
    end

    subgraph External
        OPENAI[OpenAI API<br>gpt-4o-mini]
        UPSTREAM[Google DNS<br>8.8.8.8]
    end

    DNS -->|unknown domain| API
    API -->|score request| OPENAI
    DNS -->|safe domain| UPSTREAM
    DNS -->|blocked domain| BP
    DNS -->|block event| NOTIFY
    DNS ---|read/write| DB

    style DNS fill:#fff3e0,stroke:#FF9800
    style API fill:#e3f2fd,stroke:#2196F3
    style BP fill:#ffebee,stroke:#f44336
    style DB fill:#f3e5f5,stroke:#9C27B0
```

---

## Project Structure

```
SentinelX-II26/
├── main.py                      # Entry point — launches all components
├── config.py                    # Settings (ports, thresholds, API key)
├── .env                         # OpenAI API key (not committed)
│
├── scorer/
│   ├── server.py                # FastAPI /scan endpoint
│   └── openai_scorer.py         # Calls OpenAI, returns phishing score
│
├── interceptor/
│   ├── dns_server.py            # dnslib UDP server on port 53
│   ├── dns_config.py            # netsh DNS redirect + restore
│   └── cache.py                 # SQLite cache + event logging
│
├── ui/
│   ├── tray_icon.py             # System tray icon (pystray)
│   ├── block_page.py            # Local HTTP server (port 80)
│   ├── warning.html             # Block page HTML
│   └── notify.py                # Windows toast notifications
│
├── data/
│   ├── whitelist.py             # Top domains auto-allowed
│   ├── sentinelx.db             # SQLite database (runtime)
│   └── sentinelx.log            # Full event log
│
├── tests/
│   └── generate_test_pdf.py     # Generate PDF with test links
│
└── utils/
    └── logger.py                # Console + file logging
```

---

## Quick Start

### 1. Setup
```powershell
git clone <repo-url>
cd SentinelX-II26
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### 2. Install Dependencies
```powershell
uv sync
```

### 3. Run (requires admin for DNS redirect)
```powershell
uv run python main.py
```
A UAC prompt will appear — click **Yes**. SentinelX will:
- Start the FastAPI scorer on `127.0.0.1:8000`
- Redirect Windows DNS to `127.0.0.1:53`
- Start the block page server on `127.0.0.1:80`
- Show a system tray icon

### 4. Test
```powershell
# Safe domain — should resolve normally
nslookup google.com 127.0.0.1

# Phishing domain — should return 127.0.0.1 (blocked)
nslookup arnazon-security.ml 127.0.0.1
```

Or generate a test PDF with clickable links:
```powershell
uv run python tests/generate_test_pdf.py
# Open test_links.pdf and click the links
```

### 5. Stop
- Right-click tray icon → **Stop & Restore DNS**
- Or press `Ctrl+C` in the terminal
- DNS is automatically restored

---

## Scoring Thresholds

| Score | Verdict | Action |
|-------|---------|--------|
| 0.0 – 0.3 | `allow` | Forward DNS normally |
| 0.3 – 0.7 | `warn` | Forward DNS (log as suspicious) |
| 0.7 – 1.0 | `block` | Return 127.0.0.1 + toast notification |

---

## Safety

- **DNS always restored on exit** via `atexit` + signal handlers
- **Failsafe**: if the scorer is unreachable, all traffic is ALLOWED (never breaks internet)
- **Emergency DNS restore** (if anything goes wrong):
  ```powershell
  netsh interface ip set dns "Wi-Fi" dhcp
  ipconfig /flushdns
  ```

---

## Tech Stack

| Component | Library |
|-----------|---------|
| DNS Server | `dnslib` |
| Scoring API | `FastAPI` + `uvicorn` |
| LLM Scoring | `openai` (gpt-4o-mini) |
| Cache + Logs | `aiosqlite` (SQLite) |
| System Tray | `pystray` + `Pillow` |
| Notifications | PowerShell balloon tips |
| DNS Redirect | `netsh` (Windows built-in) |
| Package Manager | `uv` |




# SentinelX — Credential Leak Monitor

Continuously watches multiple sources across the open web, paste sites, and breach databases for any mention of an organization's email domain or credentials appearing in leaked data. Alerts the security team the moment a leak is detected — before attackers can exploit it.

> **The average time between a credential breach and its discovery by the victim is 197 days** (IBM Cost of a Data Breach Report). SentinelX reduces that to minutes.

---

## Architecture

```mermaid
flowchart TD
    A[⏰ Scheduler<br>Configurable: daily at 08:00<br>or every N hours] --> B[🔄 Scan Orchestrator<br>main.py]

    B --> C[Scanner 1<br><b>HIBP Email Breach Check</b>]
    B --> D[Scanner 2<br><b>Password k-Anonymity Check</b>]
    B --> E[Scanner 3<br><b>GitHub Code Leak Search</b>]
    B --> F[Scanner 4<br><b>Paste Site Search</b>]

    C --> G[(SQLite DB<br>employees + scan_results)]
    D --> G
    E --> G
    F --> G

    G --> H{New findings<br>detected?}
    H -->|Yes| I[📧 SMTP Email Alert<br>HTML report to security team]
    H -->|No| J[✅ No action needed<br>Log clean scan]

    I --> K[Mark findings as alerted<br>Dedup: won't re-alert]

    subgraph External APIs
        C1[HIBP Breach API<br>haveibeenpwned.com/api/v3]
        C2[HIBP Pwned Passwords API<br>api.pwnedpasswords.com/range]
        C3[GitHub Search API<br>api.github.com/search/code]
        C4[Google Custom Search API<br>customsearch.googleapis.com]
    end

    C --> C1
    D --> C2
    E --> C3
    F --> C4

    style A fill:#1a2332,stroke:#00d4ff,color:#fff
    style B fill:#1a2332,stroke:#00d4ff,color:#fff
    style I fill:#2d1520,stroke:#ff4d6a,color:#fff
    style J fill:#152d1a,stroke:#2ecc71,color:#fff
    style G fill:#1a1a2e,stroke:#6c5ce7,color:#fff
```

---

## How Each Scanner Works

### Scanner 1: HIBP Email Breach Check

```mermaid
sequenceDiagram
    participant DB as Employee DB
    participant Scanner as Breach Scanner
    participant HIBP as HIBP API<br>haveibeenpwned.com

    Scanner->>DB: Get all employee emails
    loop For each employee email
        Scanner->>HIBP: GET /api/v3/breachedaccount/{email}
        Note right of HIBP: Rate limit: 1.5s between requests<br>Free tier: per-email lookup
        HIBP-->>Scanner: List of breaches<br>{Name, Date, DataClasses}
        alt Email found in breach
            Scanner->>DB: Store finding (severity: HIGH)
        else Clean
            Scanner->>DB: Log clean result
        end
        Note over Scanner: Sleep 1.5s (rate limit)
    end
```

**What it detects:** Employee emails appearing in known data breaches (LinkedIn, Adobe, Dropbox, Collection#1, etc.)

**API:** `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}` — Free for per-email lookups, no API key needed.

---

### Scanner 2: Password k-Anonymity Check (HIBP Pwned Passwords)

```mermaid
flowchart LR
    A[Employee password] --> B[SHA-1 hash locally<br><code>5BAA6...1F</code>]
    B --> C[Take first 5 chars<br><code>5BAA6</code>]
    C --> D[Send prefix to HIBP API<br>GET /range/5BAA6]
    D --> E[API returns ~500 hash suffixes<br>with occurrence counts]
    E --> F{Full hash<br>in results?}
    F -->|Yes| G[🔴 CRITICAL<br>Password is compromised<br>Found N times in breaches]
    F -->|No| H[✅ SAFE<br>Password not in any<br>known breach]

    style A fill:#1a2332,stroke:#00d4ff,color:#fff
    style G fill:#2d1520,stroke:#ff4d6a,color:#fff
    style H fill:#152d1a,stroke:#2ecc71,color:#fff
```

**Privacy guarantee:** The actual password or its full hash **never leaves the machine**. Only the first 5 characters of the SHA-1 hash are sent.

**API:** `GET https://api.pwnedpasswords.com/range/{5-char-prefix}` — Completely free, no API key, no rate limit.

---

### Scanner 3: GitHub Code Leak Search

```mermaid
sequenceDiagram
    participant Scanner as GitHub Scanner
    participant GH as GitHub Search API
    participant DB as Results DB

    loop For each keyword (password, secret, api_key, token)
        Scanner->>GH: GET /search/code?q={domain}+{keyword}
        Note right of GH: Free: 30 requests/min<br>with personal access token
        GH-->>Scanner: Matching code files<br>{repo, path, snippet}
        alt Matches found
            Scanner->>DB: Store finding<br>HIGH (password/secret) or MEDIUM (other)
        end
    end
```

**What it detects:** Developers who accidentally commit credentials, API keys, secrets, or internal URLs to public repos.

**API:** `GET https://api.github.com/search/code?q={query}` — Free with a personal access token (30 searches/minute).

**Keywords searched:** `password`, `secret`, `api_key`, `token`, `credential` + organization domain

---

### Scanner 4: Paste Site Search

```mermaid
sequenceDiagram
    participant Scanner as Paste Scanner
    participant Google as Google Custom Search API
    participant DB as Results DB

    Scanner->>Google: GET /customsearch/v1?q=site:pastebin.com+"{domain}"
    Google-->>Scanner: Matching paste URLs + snippets
    Scanner->>Google: GET /customsearch/v1?q=site:paste.ee+"{domain}"
    Google-->>Scanner: Matching paste URLs + snippets

    loop For each result
        alt Contains credentials (password, email:pass format)
            Scanner->>DB: Store finding (severity: HIGH)
        else Mention only
            Scanner->>DB: Store finding (severity: MEDIUM)
        end
    end
```

**What it detects:** Organization emails or credentials dumped on Pastebin, paste.ee, ghostbin, and similar sites.

**API:** Google Custom Search Engine — Free for 100 queries/day. Requires a Google Cloud API key + Custom Search Engine ID (both free).

---

## Alert & Response Pipeline

```mermaid
flowchart TD
    A[All scanners complete] --> B{Any new<br>findings?}
    B -->|No| C[Log: Clean scan ✅]
    B -->|Yes| D[Check dedup:<br>Has this been alerted before?]
    D -->|Already alerted| C
    D -->|New finding| E[Build HTML email report]
    E --> F[SMTP: Send to security team<br>via Gmail / corporate mail]
    F --> G[Mark finding as alerted<br>in alerts_sent table]

    E --> H[Report contains:]
    H --> H1[Summary: CRITICAL / HIGH / MEDIUM counts]
    H --> H2[Per-finding detail: email, breach, date, data exposed]
    H --> H3[k-Anonymity results: which passwords are compromised]
    H --> H4[GitHub repos with leaked credentials]
    H --> H5[Paste site URLs with dumps]

    style D fill:#1a2332,stroke:#ffc048,color:#fff
    style F fill:#2d1520,stroke:#ff4d6a,color:#fff
    style C fill:#152d1a,stroke:#2ecc71,color:#fff
```

**Trigger:** Any new breach, password match, GitHub leak, or paste dump detected.

**Action:** HTML email sent via SMTP (Gmail app password or corporate SMTP) containing full detail with severity color coding.

**Dedup:** Same finding is never alerted twice — tracked in `alerts_sent` table.

---

## Database Schema

```mermaid
erDiagram
    employees {
        int id PK
        string email UK
        string password_sha1
        string password_sha256
        string department
        string full_name
        float added_at
    }

    scan_results {
        int id PK
        int employee_id FK
        string scan_type
        string source
        string finding
        string severity
        float scanned_at
    }

    alerts_sent {
        int id PK
        int scan_result_id FK
        float alerted_at
    }

    employees ||--o{ scan_results : "has findings"
    scan_results ||--o| alerts_sent : "triggers alert"
```

---

## Project Structure

```
credential/
├── main.py                  # Entry point — scheduler, scan orchestrator, CLI
├── config.py                # All settings (schedule, SMTP, domain, API keys)
├── generate_reports.py      # Generate HTML dashboard pages
├── .env                     # Secrets (SMTP password, GitHub token, Google API key)
│
├── scanners/
│   ├── breach_scanner.py    # HIBP email breach check
│   ├── password_scanner.py  # HIBP k-Anonymity password check
│   ├── github_scanner.py    # GitHub public repo search
│   └── paste_scanner.py     # Paste site search via Google CSE
│
├── db/
│   ├── models.py            # SQLite schema, CRUD operations
│   └── seed.py              # Seed DB with sample data (prototype mode)
│
├── alerts/
│   └── email_alert.py       # SMTP HTML email sender with dedup
│
├── utils/
│   └── logger.py            # Dual logging (console + file)
│
└── data/
    ├── credleak.db          # SQLite database (runtime)
    ├── credleak.log         # Full scan log
    └── reports/             # Generated HTML pages
        ├── dashboard.html
        ├── employees.html
        ├── leaked_credentials.html
        ├── github_leaks.html
        └── paste_leaks.html
```

---

## Configuration

```python
# config.py
ORG_DOMAIN = "acmecorp.com"           # Domain to monitor
SCAN_SCHEDULE_TIME = "08:00"           # Daily scan time
SCAN_INTERVAL_HOURS = 24               # Or scan every N hours
SCAN_ON_STARTUP = True                 # Scan immediately on launch

# Toggle individual scanners
ENABLE_BREACH_SCAN = True
ENABLE_PASSWORD_SCAN = True
ENABLE_GITHUB_SCAN = True
ENABLE_PASTE_SCAN = True
```

```env
# .env
SMTP_USER=security@company.com
SMTP_PASSWORD=your-app-password
GITHUB_TOKEN=ghp_xxxxxxxxxxxx          # Free personal access token
GOOGLE_API_KEY=AIzaSyxxxxxxxxx          # Free Google Cloud API key
GOOGLE_CSE_ID=xxxxxxxxxx               # Free Custom Search Engine ID
```

---

## Usage

```powershell
# Seed database with sample data (prototype demo)
python main.py --seed

# Run a single scan + send email alert
python main.py

# Run scan without sending email
python main.py --no-email

# Run on schedule (repeat every 24 hours)
python main.py --schedule

# View recent scan results
python main.py --report

# Generate HTML report pages
python generate_reports.py
```

---

## Scoring & Severity

| Severity | Trigger | Action |
|----------|---------|--------|
| **CRITICAL** | Employee password found in breach DB (k-Anonymity match) | Immediate alert — force password reset |
| **HIGH** | Email in breach with password exposed / GitHub credential leak / Paste with credentials | Alert — investigate and rotate credentials |
| **MEDIUM** | Email in breach without password / Paste mention / GitHub non-credential keyword | Alert — monitor |
| **LOW** | Domain mention without credentials | Log only |

---

## API Costs

| Source | Cost | Rate Limit |
|--------|------|-----------|
| HIBP Pwned Passwords (k-Anonymity) | **Free** | Unlimited |
| HIBP Breach Check (per email) | **Free** | 1 request / 1.5 seconds |
| GitHub Search API | **Free** (with token) | 30 requests / minute |
| Google Custom Search | **Free** (100/day) | 100 queries / day |
| SMTP (Gmail) | **Free** | 500 emails / day |

**Total cost: $0/month** for all APIs.

---

## Security Considerations

- **Passwords are never stored in plaintext** — only SHA-1 and SHA-256 hashes
- **k-Anonymity** ensures the actual password or full hash never leaves the machine
- **SMTP credentials** stored in `.env` file (never committed to git)
- **Alert deduplication** prevents alert fatigue — same finding is never reported twice
- **Failsafe**: if any scanner or API fails, other scanners continue independently
