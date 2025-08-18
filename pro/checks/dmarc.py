
from typing import List, Dict, Tuple, Callable
QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def _row(domain, selector, value, issues, severity):
    return {"Domain": domain, "RecordType": "DMARC", "Selector": selector or "", "Value": value, "Issues": issues, "Severity": severity}

def _kv_map(txt: str):
    parts = [p.strip() for p in txt.split(";") if p.strip()]
    kv = {}
    for p in parts:
        if "=" in p:
            k,v = p.split("=",1)
            kv[k.strip()] = v.strip()
        else:
            kv[p] = ""
    return kv

def check_dmarc(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    name = f"_dmarc.{domain}"
    ok, vals, err = q(name, "TXT")
    if not ok:
        return [_row(domain, selector, "", "DMARC record not found", "CRITICAL")]
    dmarcs = []
    for v in vals:
        cleaned = v.replace('"', '').strip()
        if cleaned.lower().replace(' ', '').startswith('v=dmarc1'):
            dmarcs.append(cleaned)
    if not dmarcs:
        return [_row(domain, selector, "", "DMARC record not found", "CRITICAL")]
    if len(dmarcs) > 1:
        return [_row(domain, selector, " | ".join(dmarcs), "Multiple DMARC records", "CRITICAL")]
    rec = dmarcs[0]
    kv = _kv_map(rec)
    p = kv.get("p","").lower()
    issues = []
    sev = "OK"
    if p in ("", "none"):
        issues.append("Policy not enforcing (p=none)")
        sev = "WARN" if p=="none" else "CRITICAL"
    if "rua" not in kv:
        issues.append("No rua aggregate reports")
        sev = "WARN"
    if kv.get("pct","100")!="100":
        issues.append(f"pct={kv.get('pct')}")
        sev = "WARN"
    adkim = kv.get("adkim","r")
    aspf = kv.get("aspf","r")
    if adkim!="s" or aspf!="s":
        issues.append(f"Alignment adkim={adkim}, aspf={aspf} (suggest 's')")
        sev = "WARN"
    return [_row(domain, selector, rec, "; ".join(issues), sev)]
