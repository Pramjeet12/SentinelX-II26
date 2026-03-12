"""Paste site scanner — searches Pastebin and similar sites for leaked credentials.

In production: uses Google Custom Search API to find pastes containing the org domain.
In prototype: queries local paste_leaks table.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from db.models import get_paste_leaks_by_domain, add_scan_result, is_already_alerted
from utils.logger import setup_logger
import config

log = setup_logger("paste_scan")


def scan() -> list[dict]:
    """Search paste sites for organization domain mentions.

    Returns a list of NEW findings.
    """
    log.info(f"Starting paste site scan for domain: {config.ORG_DOMAIN}...")
    findings = []

    leaks = get_paste_leaks_by_domain(config.ORG_DOMAIN)

    if not leaks:
        log.info("  No paste site leaks found for organization domain")
        return findings

    for leak in leaks:
        paste_url = leak["paste_url"]
        title = leak["paste_title"]
        snippet = leak["snippet"]
        paste_date = leak["paste_date"]

        finding_text = (
            f"Paste '{title}' at {paste_url} contains {config.ORG_DOMAIN} "
            f"(date: {paste_date})"
        )

        if is_already_alerted("paste", paste_url, finding_text):
            log.debug(f"  SKIP (already alerted): {paste_url}")
            continue

        # Pastes with credentials are HIGH, simple mentions are MEDIUM
        has_creds = any(kw in snippet.lower() for kw in ["password", ":", "secret", "token"])
        severity = config.SEVERITY_HIGH if has_creds else config.SEVERITY_MEDIUM

        result_id = add_scan_result(
            employee_id=None,
            scan_type="paste",
            source=paste_url,
            finding=finding_text,
            severity=severity,
        )

        log.warning(
            f"  LEAK [{severity}]: {paste_url} — \"{title}\"\n"
            f"         Snippet: {snippet[:120]}..."
        )
        findings.append({
            "scan_result_id": result_id,
            "type": "paste",
            "paste_url": paste_url,
            "title": title,
            "snippet": snippet,
            "paste_date": paste_date,
            "severity": severity,
            "finding": finding_text,
        })

    log.info(f"Paste scan complete: {len(findings)} new leaks found")
    return findings
