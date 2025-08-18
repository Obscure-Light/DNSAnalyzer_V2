
from typing import List, Dict, Tuple, Callable
import re
QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def _row(domain, selector, value, issues, severity):
    return {"Domain": domain, "RecordType": "SPF", "Selector": selector or "", "Value": value, "Issues": issues, "Severity": severity}

def _parse_spf(txt: str) -> List[str]:
    # very light parser
    parts = txt.split()
    return parts[1:]  # skip v=spf1

def _lookup_cost(mech: str) -> int:
    # RFC 7208: include, a, mx, ptr, exists, redirect consume lookups
    key = mech.split(":")[0].split("/")[0]
    return 1 if key in ("include","a","mx","ptr","exists","redirect") else 0

def check_spf(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "TXT")
    if not ok:
        return [_row(domain, selector, "", f"TXT query error: {err}", "WARN")]
    spfs = [v.strip('"') for v in vals if v.replace(" ", "").lower().startswith("v=spf1")]
    if not spfs:
        return [_row(domain, selector, "", "No SPF record found", "WARN")]
    if len(spfs) > 1:
        return [_row(domain, selector, " | ".join(spfs), "Multiple SPF records (should be single)", "CRITICAL")]
    spf = spfs[0]
    mechs = _parse_spf(spf)
    lookups = sum(_lookup_cost(m) for m in mechs)
    issues = []
    sev = "OK"
    if any(m for m in mechs if m.lower()=="redirect"):
        lookups += 1
    if lookups > 10:
        issues.append(f"SPF lookup count {lookups}>10")
        sev = "CRITICAL"
    if any(m.lower()=="+all" or m.lower().endswith("all") and not m.startswith("-") for m in mechs):
        issues.append("SPF allows ALL (use -all)")
        sev = "CRITICAL"
    if not any(m.endswith("all") for m in mechs):
        issues.append("Missing 'all' mechanism")
        sev = "WARN"
    return [_row(domain, selector, spf, "; ".join(issues), sev)]
