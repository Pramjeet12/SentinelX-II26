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
