"""
SentinelX — Credential Leak Monitor
Main entry point: runs all scanners, sends alerts, supports scheduled execution.

Usage:
    python main.py              # Run once (scan + alert)
    python main.py --schedule   # Run on schedule (daily at configured time)
    python main.py --seed       # Seed the database with sample data first
"""

import sys
import time
import argparse
import threading
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from db.models import init_db, get_recent_scan_results
from db.seed import seed as seed_db
from scanners.breach_scanner import scan as breach_scan
from scanners.password_scanner import scan as password_scan
from scanners.github_scanner import scan as github_scan
from scanners.paste_scanner import scan as paste_scan
from alerts.email_alert import send_alert
from utils.logger import setup_logger
import config

log = setup_logger("main")


def run_full_scan() -> list[dict]:
    """Run all enabled scanners and collect findings."""
    log.info("=" * 60)
    log.info(f"  SentinelX Credential Leak Monitor — Full Scan")
    log.info(f"  Organization: {config.ORG_NAME} ({config.ORG_DOMAIN})")
    log.info(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("=" * 60)

    all_findings = []

    # ── Scanner 1: Breach Email Check ──
    if config.ENABLE_BREACH_SCAN:
        log.info("\n--- Scanner 1/4: Breach Email Check ---")
        findings = breach_scan()
        all_findings.extend(findings)
    else:
        log.info("--- Scanner 1/4: Breach Email Check [DISABLED] ---")

    # ── Scanner 2: Password k-Anonymity Check ──
    if config.ENABLE_PASSWORD_SCAN:
        log.info("\n--- Scanner 2/4: Password k-Anonymity Check ---")
        findings = password_scan()
        all_findings.extend(findings)
    else:
        log.info("--- Scanner 2/4: Password k-Anonymity Check [DISABLED] ---")

    # ── Scanner 3: GitHub Leak Search ──
    if config.ENABLE_GITHUB_SCAN:
        log.info("\n--- Scanner 3/4: GitHub Leak Search ---")
        findings = github_scan()
        all_findings.extend(findings)
    else:
        log.info("--- Scanner 3/4: GitHub Leak Search [DISABLED] ---")

    # ── Scanner 4: Paste Site Search ──
    if config.ENABLE_PASTE_SCAN:
        log.info("\n--- Scanner 4/4: Paste Site Search ---")
        findings = paste_scan()
        all_findings.extend(findings)
    else:
        log.info("--- Scanner 4/4: Paste Site Search [DISABLED] ---")

    # ── Results Summary ──
    log.info("\n" + "=" * 60)
    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    log.info(f"  SCAN COMPLETE — {len(all_findings)} new findings:")
    if critical:
        log.warning(f"    CRITICAL: {critical}")
    if high:
        log.warning(f"    HIGH:     {high}")
    if medium:
        log.info(f"    MEDIUM:   {medium}")
    if low:
        log.info(f"    LOW:      {low}")
    if not all_findings:
        log.info("    No new findings (either clean or already alerted)")
    log.info("=" * 60)

    return all_findings


def run_scan_and_alert():
    """Run all scanners and send email alert if findings exist."""
    init_db()
    findings = run_full_scan()

    if findings:
        log.info("\nSending alert email...")
        success = send_alert(findings)
        if success:
            log.info("Alert email sent successfully!")
        else:
            log.error("Failed to send alert email")
    else:
        log.info("No new findings — no alert sent")


def run_scheduled():
    """Run scans on a schedule (configurable interval)."""
    log.info(f"Scheduler started — scanning every {config.SCAN_INTERVAL_HOURS} hours")
    log.info(f"Next scan at: {config.SCAN_SCHEDULE_TIME} or every {config.SCAN_INTERVAL_HOURS}h")

    if config.SCAN_ON_STARTUP:
        log.info("Running initial scan on startup...")
        run_scan_and_alert()

    while True:
        log.info(f"Sleeping for {config.SCAN_INTERVAL_HOURS} hours until next scan...")
        time.sleep(config.SCAN_INTERVAL_HOURS * 3600)
        run_scan_and_alert()


def print_report():
    """Print recent scan results to console."""
    init_db()
    results = get_recent_scan_results(limit=20)

    if not results:
        print("\nNo scan results yet. Run a scan first with: python main.py")
        return

    print(f"\n{'='*80}")
    print(f"  Recent Scan Results (last {len(results)})")
    print(f"{'='*80}")
    for r in results:
        ts = datetime.fromtimestamp(r["scanned_at"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{r['severity']:8s}] {r['scan_type']:10s} | {ts} | {r['finding'][:80]}")
    print(f"{'='*80}")


def main():
    parser = argparse.ArgumentParser(description="SentinelX Credential Leak Monitor")
    parser.add_argument("--schedule", action="store_true", help="Run on schedule (repeat every N hours)")
    parser.add_argument("--seed", action="store_true", help="Seed database with sample data")
    parser.add_argument("--report", action="store_true", help="Print recent scan results")
    parser.add_argument("--no-email", action="store_true", help="Run scan without sending email")
    args = parser.parse_args()

    if args.seed:
        seed_db()
        return

    if args.report:
        print_report()
        return

    if args.schedule:
        run_scheduled()
        return

    # Default: single scan
    init_db()
    findings = run_full_scan()

    if findings and not args.no_email:
        log.info("\nSending alert email...")
        send_alert(findings)
    elif findings:
        log.info(f"\n{len(findings)} findings detected (email skipped — --no-email)")


if __name__ == "__main__":
    main()
