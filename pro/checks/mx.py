
from typing import List, Tuple, Callable
from .utils import make_row
QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def check_mx(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "MX")
    if not ok or not vals:
        return [make_row(domain, "MX", selector, "", "No MX", "CRITICAL")]
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
    return [make_row(domain, "MX", selector, "; ".join([f"{p} {h}" for p,h in entries]).strip(), "; ".join(issues), sev)]
