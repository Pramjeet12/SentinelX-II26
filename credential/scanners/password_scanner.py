"""Password k-Anonymity scanner — checks if employee passwords appear in leaked data.

Uses the HIBP k-Anonymity model:
  1. SHA-1 hash the password locally
  2. Take first 5 characters of the hash as prefix
  3. Query ALL leaked hashes with that prefix (simulated via local DB)
  4. Check if the employee's FULL hash appears in the results
  5. The actual password NEVER leaves the machine

In production: calls api.pwnedpasswords.com/range/{prefix}
In prototype: queries leaked_credentials table by SHA-1 prefix
"""

import hashlib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from db.models import get_all_employees, get_leaked_by_sha1_prefix, add_scan_result, is_already_alerted
from utils.logger import setup_logger
import config

log = setup_logger("password_scan")

K_ANON_PREFIX_LENGTH = 5  # First 5 chars of SHA-1 hash


def scan() -> list[dict]:
    """Check every employee's password hash against the breach DB using k-Anonymity.

    Returns a list of NEW findings (passwords found in breaches).
    """
    log.info("Starting password k-Anonymity scan...")
    employees = get_all_employees()
    findings = []

    for emp in employees:
        email = emp["email"]
        full_sha1 = emp["password_sha1"]  # Already stored as SHA-1 hash
        prefix = full_sha1[:K_ANON_PREFIX_LENGTH]
        suffix = full_sha1[K_ANON_PREFIX_LENGTH:]

        log.debug(f"  Checking {email}: SHA1 prefix={prefix}...")

        # k-Anonymity query: get all hashes starting with this prefix
        matches = get_leaked_by_sha1_prefix(prefix)

        # Check if our full hash is in the results
        password_found = False
        matched_breaches = []
        for match in matches:
            if match["password_hash"] == full_sha1:
                password_found = True
                matched_breaches.append(match["breach_name"])

        if not password_found:
            log.debug(f"  SAFE: {email} — password hash not found ({len(matches)} hashes checked)")
            continue

        # Password is compromised!
        breach_list = ", ".join(set(matched_breaches))
        finding_text = (
            f"Password for '{email}' found in {len(matched_breaches)} breach(es): {breach_list} "
            f"[k-Anonymity: prefix={prefix}, {len(matches)} candidates checked]"
        )

        if is_already_alerted("password", breach_list, finding_text):
            log.debug(f"  SKIP (already alerted): {email}")
            continue

        severity = config.SEVERITY_CRITICAL  # Password match is always CRITICAL

        result_id = add_scan_result(
            employee_id=emp["id"],
            scan_type="password",
            source=breach_list,
            finding=finding_text,
            severity=severity,
        )

        log.warning(
            f"  COMPROMISED [{severity}]: {email} — password found in: {breach_list} "
            f"(k-Anon: prefix={prefix}, {len(matches)} hashes checked)"
        )
        findings.append({
            "scan_result_id": result_id,
            "type": "password",
            "email": email,
            "employee_name": emp["full_name"],
            "department": emp["department"],
            "breaches": breach_list,
            "k_anon_prefix": prefix,
            "candidates_checked": len(matches),
            "severity": severity,
            "finding": finding_text,
        })

    log.info(f"Password scan complete: {len(findings)} compromised passwords from {len(employees)} employees")
    return findings
