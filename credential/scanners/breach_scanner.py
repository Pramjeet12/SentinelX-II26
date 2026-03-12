"""Breach email scanner — checks if employee emails appear in known breaches.

In production: calls HIBP API per email.
In prototype: queries local leaked_credentials table.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from db.models import get_all_employees, get_leaked_by_email, add_scan_result, is_already_alerted
from utils.logger import setup_logger
import config

log = setup_logger("breach_scan")


def scan() -> list[dict]:
    """Check every employee email against the breach database.

    Returns a list of NEW findings (not previously alerted).
    """
    log.info("Starting breach email scan...")
    employees = get_all_employees()
    findings = []

    for emp in employees:
        email = emp["email"]
        leaks = get_leaked_by_email(email)

        if not leaks:
            log.debug(f"  CLEAN: {email} — not found in any breach")
            continue

        for leak in leaks:
            breach = leak["breach_name"]
            data_types = leak["data_types"]
            breach_date = leak["breach_date"]

            finding_text = (
                f"Email '{email}' found in breach '{breach}' "
                f"(date: {breach_date}, exposed: {data_types})"
            )

            # Skip if already alerted
            if is_already_alerted("breach", breach, finding_text):
                log.debug(f"  SKIP (already alerted): {email} in {breach}")
                continue

            # Determine severity based on what was leaked
            if "password" in data_types:
                severity = config.SEVERITY_HIGH
            elif "internal_data" in data_types:
                severity = config.SEVERITY_HIGH
            else:
                severity = config.SEVERITY_MEDIUM

            result_id = add_scan_result(
                employee_id=emp["id"],
                scan_type="breach",
                source=breach,
                finding=finding_text,
                severity=severity,
            )

            log.warning(f"  FOUND [{severity}]: {email} in {breach} (exposed: {data_types})")
            findings.append({
                "scan_result_id": result_id,
                "type": "breach",
                "email": email,
                "employee_name": emp["full_name"],
                "department": emp["department"],
                "breach_name": breach,
                "breach_date": breach_date,
                "data_exposed": data_types,
                "severity": severity,
                "finding": finding_text,
            })

    log.info(f"Breach scan complete: {len(findings)} new findings from {len(employees)} employees")
    return findings
