"""Seed the database with sample employees and simulated breach data.

This creates a realistic prototype scenario:
- 8 company employees
- A simulated breach database with leaked credentials (some matching our employees)
- Simulated GitHub code leaks
- Simulated paste site leaks
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from db.models import (
    init_db, add_employee, add_leaked_credential,
    add_github_leak, add_paste_leak, get_db,
)
import config


def seed():
    print("=" * 50)
    print("  Seeding Credential Leak Monitor Database")
    print("=" * 50)

    init_db()

    # Clear existing data for clean re-seed
    conn = get_db()
    for table in ["alerts_sent", "scan_results", "paste_leaks", "github_leaks", "leaked_credentials", "employees"]:
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()

    # ── Company Employees ──
    # Some of these will have their credentials "leaked" in our simulated breach DB
    employees = [
        ("john.smith@acmecorp.com",      "Welcome123!",      "Engineering",  "John Smith"),
        ("sarah.jones@acmecorp.com",      "S@rah2024Secure",  "Finance",      "Sarah Jones"),
        ("mike.wilson@acmecorp.com",      "P@ssw0rd!",        "HR",           "Mike Wilson"),
        ("emma.davis@acmecorp.com",       "Emma$tr0ng99",     "Engineering",  "Emma Davis"),
        ("alex.kumar@acmecorp.com",       "AlexKumar#2025",   "Marketing",    "Alex Kumar"),
        ("lisa.chen@acmecorp.com",        "Qwerty123!",       "Engineering",  "Lisa Chen"),
        ("raj.patel@acmecorp.com",        "Raj!Secure456",    "Operations",   "Raj Patel"),
        ("admin@acmecorp.com",            "Admin@1234",       "IT",           "System Admin"),
    ]

    print("\n[+] Adding employees...")
    for email, password, dept, name in employees:
        add_employee(email, password, dept, name)
        print(f"    {email} ({dept})")

    # ── Simulated Breach Database ──
    # These simulate what HIBP / DeHashed would return
    # Some emails/passwords match our employees (those are the "hits")
    leaked = [
        # !! MATCH: john.smith uses "Welcome123!" — same password leaked in LinkedIn breach
        ("john.smith@acmecorp.com",  "Welcome123!",     "LinkedIn2024",     "2024-06-15", "email,password"),
        # !! MATCH: mike.wilson uses "P@ssw0rd!" — same as leaked in Adobe breach
        ("mike.wilson@acmecorp.com", "P@ssw0rd!",       "AdobeHack2023",    "2023-11-20", "email,password,name"),
        # !! MATCH: lisa.chen uses "Qwerty123!" — weak password, leaked in Collection#1
        ("lisa.chen@acmecorp.com",   "Qwerty123!",      "Collection1",      "2019-01-17", "email,password"),
        # !! MATCH: admin uses "Admin@1234"
        ("admin@acmecorp.com",       "Admin@1234",       "CompanyBreach2025","2025-09-01", "email,password,internal_data"),

        # Email found in breach, but DIFFERENT password (password-only check won't match)
        ("sarah.jones@acmecorp.com", "OldPassword99",    "Dropbox2022",      "2022-03-10", "email,password"),
        ("emma.davis@acmecorp.com",  "RandomOld!Pass",   "MyFitnessPal2023", "2023-08-05", "email,password"),

        # External people (not our employees) — also in breach DB to make it realistic
        ("random.user@gmail.com",     "password123",     "LinkedIn2024",     "2024-06-15", "email,password"),
        ("hacker@evil.com",           "l33th4x0r",       "Collection1",      "2019-01-17", "email,password"),
        ("jane.doe@othercorp.com",    "JaneDoe2024!",    "AdobeHack2023",    "2023-11-20", "email,password"),

        # More acmecorp leaks from different breaches (password NOT matching current)
        ("john.smith@acmecorp.com",  "OldJohnPass2020",  "Canva2020",        "2020-05-24", "email,password"),
        ("alex.kumar@acmecorp.com",  "SomeOtherPass",    "Twitter2023",      "2023-01-05", "email,username"),
        ("raj.patel@acmecorp.com",   "DifferentPass!1",  "Wattpad2021",      "2021-06-14", "email,password"),
    ]

    print("\n[+] Populating simulated breach database...")
    for email, pwd, breach, date, types in leaked:
        add_leaked_credential(email, pwd, breach, date, types)
        print(f"    {breach}: {email}")

    # ── Simulated GitHub Leaks ──
    github_leaks = [
        (
            "devuser42/internal-scripts",
            "deploy/config.yaml",
            "password",
            "acmecorp.com",
            'db_host: db.acmecorp.com\ndb_user: admin@acmecorp.com\ndb_password: "Admin@1234"\ndb_name: production',
            "2025-12-10",
        ),
        (
            "contractor-dev/project-alpha",
            "src/settings.py",
            "api_key",
            "acmecorp.com",
            'API_KEY = "sk-acme-prod-7f8a9b2c3d"\n# AcmeCorp production API\nBASE_URL = "https://api.acmecorp.com"',
            "2026-01-22",
        ),
        (
            "newbie-dev99/my-notes",
            ".env.backup",
            "secret",
            "acmecorp.com",
            'SMTP_USER=admin@acmecorp.com\nSMTP_PASS=Admin@1234\nSECRET_KEY=acme-super-secret-key-2025',
            "2026-02-05",
        ),
    ]

    print("\n[+] Adding simulated GitHub leaks...")
    for repo, fpath, kw, domain, snippet, date in github_leaks:
        add_github_leak(repo, fpath, kw, domain, snippet, date)
        print(f"    {repo}/{fpath} (keyword: {kw})")

    # ── Simulated Paste Site Leaks ──
    paste_leaks = [
        (
            "https://pastebin.com/Ab3xK9z2",
            "AcmeCorp Employee Dump 2025",
            "acmecorp.com",
            "john.smith@acmecorp.com:Welcome123!\nmike.wilson@acmecorp.com:P@ssw0rd!\nlisa.chen@acmecorp.com:Qwerty123!",
            "2025-11-30",
        ),
        (
            "https://paste.ee/p/8kLm2Q",
            "Corporate email list",
            "acmecorp.com",
            "=== acmecorp.com emails ===\nadmin@acmecorp.com\njohn.smith@acmecorp.com\nsarah.jones@acmecorp.com\n[SOURCE: internal breach]",
            "2026-01-15",
        ),
    ]

    print("\n[+] Adding simulated paste site leaks...")
    for url, title, domain, snippet, date in paste_leaks:
        add_paste_leak(url, title, domain, snippet, date)
        print(f"    {url} — {title}")

    # ── Summary ──
    conn = get_db()
    emp_count = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    leak_count = conn.execute("SELECT COUNT(*) FROM leaked_credentials").fetchone()[0]
    gh_count = conn.execute("SELECT COUNT(*) FROM github_leaks").fetchone()[0]
    paste_count = conn.execute("SELECT COUNT(*) FROM paste_leaks").fetchone()[0]
    conn.close()

    print("\n" + "=" * 50)
    print(f"  Database seeded successfully!")
    print(f"  Employees:       {emp_count}")
    print(f"  Breach records:  {leak_count}")
    print(f"  GitHub leaks:    {gh_count}")
    print(f"  Paste leaks:     {paste_count}")
    print("=" * 50)


if __name__ == "__main__":
    seed()
