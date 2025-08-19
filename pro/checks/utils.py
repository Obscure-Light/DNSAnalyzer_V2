from typing import Dict

def make_row(domain: str, rtype: str, selector: str, value: str, issues: str, severity: str) -> Dict[str, str]:
    return {
        "Domain": domain,
        "RecordType": rtype,
        "Selector": selector or "",
        "Value": value,
        "Issues": issues,
        "Severity": severity,
    }
