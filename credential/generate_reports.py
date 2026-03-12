"""Generate HTML report pages from the database for presentation / demo.

Generates:
  1. employees.html        — Company employees being monitored
  2. leaked_credentials.html — Simulated breach database
  3. dashboard.html        — Scan results + findings summary
  4. github_leaks.html     — GitHub code leaks
  5. paste_leaks.html      — Paste site leaks

All pages are self-contained (inline CSS, no external deps) and interlinked.
"""

import sys
import hashlib
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from db.models import init_db, get_db, get_recent_scan_results
import config

OUTPUT_DIR = Path(__file__).parent / "data" / "reports"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Shared CSS + Layout ──

COMMON_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', -apple-system, sans-serif;
    background: #0f1923;
    color: #e0e6ed;
    min-height: 100vh;
}
.navbar {
    background: linear-gradient(135deg, #1a2332 0%, #0d1b2a 100%);
    border-bottom: 2px solid #00d4ff33;
    padding: 16px 32px;
    display: flex;
    align-items: center;
    gap: 32px;
}
.navbar .logo {
    font-size: 20px;
    font-weight: 700;
    color: #00d4ff;
    letter-spacing: 1px;
}
.navbar a {
    color: #8899aa;
    text-decoration: none;
    font-size: 14px;
    padding: 6px 14px;
    border-radius: 6px;
    transition: all 0.2s;
}
.navbar a:hover, .navbar a.active {
    color: #00d4ff;
    background: #00d4ff15;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 24px;
}
h1 {
    font-size: 28px;
    margin-bottom: 8px;
    color: #fff;
}
.subtitle {
    color: #6b7f94;
    font-size: 14px;
    margin-bottom: 28px;
}
.stat-cards {
    display: flex;
    gap: 16px;
    margin-bottom: 28px;
    flex-wrap: wrap;
}
.stat-card {
    background: #1a2332;
    border: 1px solid #2a3a4a;
    border-radius: 12px;
    padding: 20px 24px;
    min-width: 180px;
    flex: 1;
}
.stat-card .label { color: #6b7f94; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
.stat-card .value { font-size: 32px; font-weight: 700; margin-top: 4px; }
.stat-card.critical .value { color: #ff4d6a; }
.stat-card.high .value { color: #ff9f43; }
.stat-card.medium .value { color: #ffc048; }
.stat-card.info .value { color: #00d4ff; }
.stat-card.safe .value { color: #2ecc71; }
table {
    width: 100%;
    border-collapse: collapse;
    background: #1a2332;
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid #2a3a4a;
}
thead th {
    background: #0d1b2a;
    padding: 14px 16px;
    text-align: left;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #6b7f94;
    border-bottom: 2px solid #2a3a4a;
}
tbody td {
    padding: 12px 16px;
    border-bottom: 1px solid #1e2d3d;
    font-size: 14px;
}
tbody tr:hover { background: #1e2d3d; }
tbody tr:last-child td { border-bottom: none; }
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
}
.badge-critical { background: #ff4d6a22; color: #ff4d6a; border: 1px solid #ff4d6a44; }
.badge-high { background: #ff9f4322; color: #ff9f43; border: 1px solid #ff9f4344; }
.badge-medium { background: #ffc04822; color: #ffc048; border: 1px solid #ffc04844; }
.badge-low { background: #00d4ff22; color: #00d4ff; border: 1px solid #00d4ff44; }
.badge-dept { background: #6c5ce722; color: #a29bfe; border: 1px solid #6c5ce744; }
.badge-safe { background: #2ecc7122; color: #2ecc71; border: 1px solid #2ecc7144; }
.match-indicator { color: #ff4d6a; font-weight: 700; }
.code-snippet {
    background: #0d1b2a;
    border: 1px solid #2a3a4a;
    border-radius: 8px;
    padding: 12px 16px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
    color: #a0b0c0;
    white-space: pre-wrap;
    word-break: break-all;
    margin-top: 4px;
}
.footer {
    text-align: center;
    padding: 32px;
    color: #3a4a5a;
    font-size: 12px;
}
"""


def nav_html(active: str) -> str:
    pages = [
        ("dashboard.html", "Dashboard"),
        ("employees.html", "Employees"),
        ("leaked_credentials.html", "Breach DB"),
        ("github_leaks.html", "GitHub Leaks"),
        ("paste_leaks.html", "Paste Leaks"),
    ]
    links = ""
    for href, label in pages:
        cls = ' class="active"' if href.startswith(active) else ""
        links += f'<a href="{href}"{cls}>{label}</a>\n'
    return f"""
    <nav class="navbar">
        <span class="logo">🛡️ SentinelX</span>
        {links}
    </nav>"""


def page_template(title: str, active: str, body: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} — SentinelX</title>
    <style>{COMMON_CSS}</style>
</head>
<body>
    {nav_html(active)}
    <div class="container">
        {body}
    </div>
    <div class="footer">
        SentinelX Credential Leak Monitor — Report generated: {ts}<br>
        Organization: {config.ORG_NAME} ({config.ORG_DOMAIN})
    </div>
</body>
</html>"""


# ── Page Generators ──

def generate_employees_page():
    conn = get_db()
    employees = conn.execute("SELECT * FROM employees ORDER BY department, email").fetchall()
    conn.close()

    dept_counts = {}
    for e in employees:
        d = e["department"]
        dept_counts[d] = dept_counts.get(d, 0) + 1

    cards = f"""
    <div class="stat-cards">
        <div class="stat-card info"><div class="label">Total Employees</div><div class="value">{len(employees)}</div></div>
        <div class="stat-card"><div class="label">Departments</div><div class="value">{len(dept_counts)}</div></div>
        <div class="stat-card"><div class="label">Domain</div><div class="value" style="font-size:18px;">{config.ORG_DOMAIN}</div></div>
    </div>"""

    rows = ""
    for i, e in enumerate(employees, 1):
        sha1_display = e["password_sha1"][:12] + "..."
        rows += f"""
        <tr>
            <td>{i}</td>
            <td><strong>{e['full_name']}</strong></td>
            <td>{e['email']}</td>
            <td><span class="badge badge-dept">{e['department']}</span></td>
            <td><code style="color:#6b7f94;font-size:12px;">{sha1_display}</code></td>
        </tr>"""

    body = f"""
    <h1>👥 Company Employees</h1>
    <p class="subtitle">Employees being monitored for credential leaks — passwords stored as SHA-1 hashes only (k-Anonymity safe)</p>
    {cards}
    <table>
        <thead>
            <tr><th>#</th><th>Name</th><th>Email</th><th>Department</th><th>Password Hash (SHA-1)</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>"""

    return page_template("Employees", "employees", body)


def generate_leaked_credentials_page():
    conn = get_db()
    leaks = conn.execute("SELECT * FROM leaked_credentials ORDER BY breach_date DESC").fetchall()
    employees = conn.execute("SELECT email, password_sha1 FROM employees").fetchall()
    conn.close()

    emp_emails = {e["email"] for e in employees}
    emp_hashes = {e["password_sha1"] for e in employees}

    breach_names = set()
    domain_match = 0
    password_match = 0
    for l in leaks:
        breach_names.add(l["breach_name"])
        if l["email"] in emp_emails:
            domain_match += 1
        if l["password_hash"] in emp_hashes:
            password_match += 1

    cards = f"""
    <div class="stat-cards">
        <div class="stat-card info"><div class="label">Total Records</div><div class="value">{len(leaks)}</div></div>
        <div class="stat-card"><div class="label">Unique Breaches</div><div class="value">{len(breach_names)}</div></div>
        <div class="stat-card high"><div class="label">Email Matches</div><div class="value">{domain_match}</div></div>
        <div class="stat-card critical"><div class="label">Password Matches</div><div class="value">{password_match}</div></div>
    </div>"""

    rows = ""
    for i, l in enumerate(leaks, 1):
        email_match = l["email"] in emp_emails
        pwd_match = l["password_hash"] in emp_hashes

        email_cell = f'<span class="match-indicator">⚠ {l["email"]}</span>' if email_match else l["email"]
        hash_display = l["password_hash"][:16] + "..."
        pwd_cell = f'<span class="match-indicator">🔴 {hash_display}</span>' if pwd_match else f'<span style="color:#6b7f94">{hash_display}</span>'

        status = ""
        if pwd_match:
            status = '<span class="badge badge-critical">PASSWORD MATCH</span>'
        elif email_match:
            status = '<span class="badge badge-high">EMAIL MATCH</span>'
        else:
            status = '<span class="badge badge-safe">No Match</span>'

        rows += f"""
        <tr>
            <td>{i}</td>
            <td>{email_cell}</td>
            <td>{pwd_cell}</td>
            <td><strong>{l['breach_name']}</strong></td>
            <td>{l['breach_date']}</td>
            <td>{l['data_types']}</td>
            <td>{status}</td>
        </tr>"""

    body = f"""
    <h1>🗄️ Breach Database</h1>
    <p class="subtitle">Leaked credentials from known data breaches — cross-referenced with company employees</p>
    {cards}
    <table>
        <thead>
            <tr><th>#</th><th>Email</th><th>Password Hash (SHA-1)</th><th>Breach</th><th>Date</th><th>Data Exposed</th><th>Match Status</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    <p style="margin-top:16px;color:#6b7f94;font-size:13px;">
        <span class="match-indicator">⚠</span> = Email belongs to an employee &nbsp;&nbsp;
        <span class="match-indicator">🔴</span> = Password hash matches an employee's current password (CRITICAL)
    </p>"""

    return page_template("Breach Database", "leaked_credentials", body)


def generate_github_leaks_page():
    conn = get_db()
    leaks = conn.execute("SELECT * FROM github_leaks ORDER BY found_date DESC").fetchall()
    conn.close()

    rows = ""
    for i, l in enumerate(leaks, 1):
        kw = l["matched_keyword"]
        severity = "HIGH" if kw in ("password", "secret", "credential") else "MEDIUM"
        badge_cls = "badge-high" if severity == "HIGH" else "badge-medium"

        rows += f"""
        <tr>
            <td>{i}</td>
            <td><strong>{l['repo_name']}</strong></td>
            <td>{l['file_path']}</td>
            <td><span class="badge {badge_cls}">{kw}</span></td>
            <td>{l['found_date']}</td>
            <td><div class="code-snippet">{l['snippet']}</div></td>
        </tr>"""

    cards = f"""
    <div class="stat-cards">
        <div class="stat-card high"><div class="label">GitHub Leaks Found</div><div class="value">{len(leaks)}</div></div>
        <div class="stat-card"><div class="label">Domain Monitored</div><div class="value" style="font-size:18px;">{config.ORG_DOMAIN}</div></div>
    </div>"""

    body = f"""
    <h1>🐙 GitHub Code Leaks</h1>
    <p class="subtitle">Public GitHub repositories containing organization credentials or secrets</p>
    {cards}
    <table>
        <thead>
            <tr><th>#</th><th>Repository</th><th>File</th><th>Keyword</th><th>Found</th><th>Code Snippet</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>"""

    return page_template("GitHub Leaks", "github_leaks", body)


def generate_paste_leaks_page():
    conn = get_db()
    leaks = conn.execute("SELECT * FROM paste_leaks ORDER BY paste_date DESC").fetchall()
    conn.close()

    rows = ""
    for i, l in enumerate(leaks, 1):
        has_creds = any(kw in l["snippet"].lower() for kw in ["password", ":", "secret", "token"])
        badge = '<span class="badge badge-high">Has Credentials</span>' if has_creds else '<span class="badge badge-medium">Mention Only</span>'

        rows += f"""
        <tr>
            <td>{i}</td>
            <td><strong>{l['paste_title']}</strong></td>
            <td><a href="{l['paste_url']}" style="color:#00d4ff;" target="_blank">{l['paste_url']}</a></td>
            <td>{l['paste_date']}</td>
            <td>{badge}</td>
            <td><div class="code-snippet">{l['snippet']}</div></td>
        </tr>"""

    cards = f"""
    <div class="stat-cards">
        <div class="stat-card high"><div class="label">Paste Leaks Found</div><div class="value">{len(leaks)}</div></div>
    </div>"""

    body = f"""
    <h1>📋 Paste Site Leaks</h1>
    <p class="subtitle">Pastebin, paste.ee, and other paste sites containing organization data</p>
    {cards}
    <table>
        <thead>
            <tr><th>#</th><th>Title</th><th>URL</th><th>Date</th><th>Type</th><th>Content</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>"""

    return page_template("Paste Leaks", "paste_leaks", body)


def generate_dashboard_page():
    conn = get_db()
    emp_count = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    leak_count = conn.execute("SELECT COUNT(*) FROM leaked_credentials").fetchone()[0]
    gh_count = conn.execute("SELECT COUNT(*) FROM github_leaks").fetchone()[0]
    paste_count = conn.execute("SELECT COUNT(*) FROM paste_leaks").fetchone()[0]

    results = conn.execute(
        "SELECT * FROM scan_results ORDER BY scanned_at DESC LIMIT 30"
    ).fetchall()

    critical = sum(1 for r in results if r["severity"] == "CRITICAL")
    high = sum(1 for r in results if r["severity"] == "HIGH")
    medium = sum(1 for r in results if r["severity"] == "MEDIUM")
    low = sum(1 for r in results if r["severity"] == "LOW")
    conn.close()

    cards = f"""
    <div class="stat-cards">
        <div class="stat-card critical"><div class="label">Critical</div><div class="value">{critical}</div></div>
        <div class="stat-card high"><div class="label">High</div><div class="value">{high}</div></div>
        <div class="stat-card medium"><div class="label">Medium</div><div class="value">{medium}</div></div>
        <div class="stat-card info"><div class="label">Total Findings</div><div class="value">{len(results)}</div></div>
    </div>
    <div class="stat-cards">
        <div class="stat-card"><div class="label">Employees Monitored</div><div class="value">{emp_count}</div></div>
        <div class="stat-card"><div class="label">Breach Records</div><div class="value">{leak_count}</div></div>
        <div class="stat-card"><div class="label">GitHub Leaks</div><div class="value">{gh_count}</div></div>
        <div class="stat-card"><div class="label">Paste Leaks</div><div class="value">{paste_count}</div></div>
    </div>"""

    rows = ""
    for i, r in enumerate(results, 1):
        ts = datetime.fromtimestamp(r["scanned_at"]).strftime("%Y-%m-%d %H:%M")
        sev = r["severity"]
        badge_cls = {"CRITICAL": "badge-critical", "HIGH": "badge-high", "MEDIUM": "badge-medium", "LOW": "badge-low"}.get(sev, "badge-low")
        scan_type = r["scan_type"].upper()

        rows += f"""
        <tr>
            <td>{i}</td>
            <td><span class="badge {badge_cls}">{sev}</span></td>
            <td>{scan_type}</td>
            <td>{r['source']}</td>
            <td style="font-size:13px;">{r['finding'][:100]}{'...' if len(r['finding']) > 100 else ''}</td>
            <td style="color:#6b7f94;font-size:12px;">{ts}</td>
        </tr>"""

    body = f"""
    <h1>📊 Scan Dashboard</h1>
    <p class="subtitle">Overview of all credential leak findings for {config.ORG_NAME} ({config.ORG_DOMAIN})</p>
    {cards}

    <h2 style="margin-top:32px;margin-bottom:16px;color:#fff;">Recent Findings</h2>
    <table>
        <thead>
            <tr><th>#</th><th>Severity</th><th>Type</th><th>Source</th><th>Finding</th><th>Time</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>"""

    return page_template("Dashboard", "dashboard", body)


def generate_all():
    init_db()

    pages = [
        ("dashboard.html", generate_dashboard_page),
        ("employees.html", generate_employees_page),
        ("leaked_credentials.html", generate_leaked_credentials_page),
        ("github_leaks.html", generate_github_leaks_page),
        ("paste_leaks.html", generate_paste_leaks_page),
    ]

    print("=" * 50)
    print("  Generating HTML Report Pages")
    print("=" * 50)

    for filename, generator in pages:
        html = generator()
        path = OUTPUT_DIR / filename
        path.write_text(html, encoding="utf-8")
        print(f"  ✓ {path}")

    print(f"\nAll pages saved to: {OUTPUT_DIR}")
    print(f"Open {OUTPUT_DIR / 'dashboard.html'} in a browser to view")


if __name__ == "__main__":
    generate_all()
