"""GitHub leak scanner — searches for organization credentials in public repos.

In production: calls GitHub Search API with domain + keywords.
In prototype: queries local github_leaks table.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from db.models import get_github_leaks_by_domain, add_scan_result, is_already_alerted
from utils.logger import setup_logger
import config

log = setup_logger("github_scan")


def scan() -> list[dict]:
    """Search for organization credentials leaked in GitHub public repos.

    Returns a list of NEW findings.
    """
    log.info(f"Starting GitHub leak scan for domain: {config.ORG_DOMAIN}...")
    findings = []

    leaks = get_github_leaks_by_domain(config.ORG_DOMAIN)

    if not leaks:
        log.info("  No GitHub leaks found for organization domain")
        return findings

    for leak in leaks:
        repo = leak["repo_name"]
        fpath = leak["file_path"]
        keyword = leak["matched_keyword"]
        snippet = leak["snippet"]
        found_date = leak["found_date"]

        finding_text = (
            f"GitHub repo '{repo}' file '{fpath}' contains {config.ORG_DOMAIN} "
            f"with keyword '{keyword}' (found: {found_date})"
        )

        if is_already_alerted("github", repo, finding_text):
            log.debug(f"  SKIP (already alerted): {repo}/{fpath}")
            continue

        # Determine severity: passwords/secrets are HIGH, other mentions are MEDIUM
        if keyword in ("password", "secret", "credential"):
            severity = config.SEVERITY_HIGH
        else:
            severity = config.SEVERITY_MEDIUM

        result_id = add_scan_result(
            employee_id=None,
            scan_type="github",
            source=repo,
            finding=finding_text,
            severity=severity,
        )

        log.warning(
            f"  LEAK [{severity}]: {repo}/{fpath} — keyword '{keyword}'\n"
            f"         Snippet: {snippet[:100]}..."
        )
        findings.append({
            "scan_result_id": result_id,
            "type": "github",
            "repo": repo,
            "file_path": fpath,
            "keyword": keyword,
            "snippet": snippet,
            "found_date": found_date,
            "severity": severity,
            "finding": finding_text,
        })

    log.info(f"GitHub scan complete: {len(findings)} new leaks found")
    return findings
