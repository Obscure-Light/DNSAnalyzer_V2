
from typing import List, Tuple, Callable
from .utils import make_row
QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def _kv(txt: str):
    kv = {}
    for part in [p.strip() for p in txt.split(";")]:
        if "=" in part:
            k,v = part.split("=",1)
            kv[k.strip()] = v.strip()
    return kv

def check_bimi(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    if not selector:
        selector = "default"
    name = f"{selector}._bimi.{domain}"
    ok, vals, err = q(name, "TXT")
    if not ok:
        return [make_row(domain, "BIMI", selector, "", "BIMI record not found", "INFO")]
    txt = " ".join(v.strip('"') for v in vals)
    kv = _kv(txt)
    issues = []
    sev = "OK"
    if "l" not in kv:
        issues.append("Missing l= (SVG logo URL)")
        sev = "WARN"
    if "a" not in kv:
        issues.append("Missing a= (VMC)")
        sev = "INFO"
    return [make_row(domain, "BIMI", selector, txt, "; ".join(issues), sev)]
