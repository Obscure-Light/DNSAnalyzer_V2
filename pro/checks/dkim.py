
from typing import List, Tuple, Callable
import base64
from .utils import make_row
QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def _kv(txt: str):
    kv = {}
    for part in [p.strip() for p in txt.split(";")]:
        if "=" in part:
            k,v = part.split("=",1)
            kv[k.strip()] = v.strip()
    return kv

def _estimate_bits_from_p(p_b64: str) -> int:
    try:
        raw = base64.b64decode(p_b64 + "===")
        # Heuristic: RSA modulus size is len(bytes)*8 bits
        return len(raw)*8
    except Exception:
        return 0

def check_dkim(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    if not selector:
        selector = "default"
    name = f"{selector}._domainkey.{domain}"
    ok, vals, err = q(name, "TXT")
    if not ok or not vals:
        return [make_row(domain, "DKIM", selector, "", "DKIM selector not found", "CRITICAL")]
    # Some providers split across multiple strings; join
    txt = "".join(v.strip('"') for v in vals)
    # If multiple records, report separately
    recs = [r.strip() for r in txt.split('" "') if r.strip()]
    if len(recs) > 1:
        return [make_row(domain, "DKIM", selector, " | ".join(recs), "Multiple DKIM TXT for selector", "CRITICAL")]
    kv = _kv(txt)
    p = kv.get("p","")
    bits = _estimate_bits_from_p(p) if p else 0
    sev = "OK"
    issues = []
    if not p:
        issues.append("Missing public key p=")
        sev = "CRITICAL"
    elif bits and bits < 1024:
        issues.append(f"Key length ~{bits} bits (too short)")
        sev = "CRITICAL"
    elif bits and bits < 2048:
        issues.append(f"Key length ~{bits} bits (consider 2048+)")
        sev = "WARN"
    if kv.get("t","")=="y":
        issues.append("Testing mode t=y")
        sev = "WARN"
    return [make_row(domain, "DKIM", selector, txt, "; ".join(issues), sev)]
