
from typing import List, Dict, Tuple, Callable
QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def _row(domain, selector, value, issues, severity):
    return {"Domain": domain, "RecordType": "MX", "Selector": selector or "", "Value": value, "Issues": issues, "Severity": severity}

def check_mx(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "MX")
    if not ok or not vals:
        return [_row(domain, selector, "", "No MX", "CRITICAL")]
    # Values are like "10 mail.example.com."
    entries = []
    for v in vals:
        parts = v.split()
        if len(parts) == 2:
            prio, host = parts
        else:
            prio, host = "", v
        entries.append((prio, host.rstrip(".")))
    sev = "OK"
    issues = []
    if len(entries) == 1:
        issues.append("Single MX (no redundancy)")
        sev = "WARN"
    return [_row(domain, selector, "; ".join([f"{p} {h}" for p,h in entries]).strip(), "; ".join(issues), sev)]
