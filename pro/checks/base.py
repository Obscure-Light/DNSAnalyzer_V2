
from typing import List, Dict, Tuple, Callable
import re

QueryFunc = Callable[[str, str], Tuple[bool, List[str], str]]

def _row(domain: str, rtype: str, selector: str, value: str, issues: str, severity: str) -> Dict[str,str]:
    return {"Domain": domain, "RecordType": rtype, "Selector": selector or "", "Value": value, "Issues": issues, "Severity": severity}

def _ok(domain, rtype, selector, values):
    if not values:
        return [_row(domain, rtype, selector, "", "Record not found", "WARN")]
    return [_row(domain, rtype, selector, "; ".join(values), "", "OK")]

def check_a(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "A")
    if not ok:
        return [_row(domain, "A", selector, "", err, "WARN")]
    return _ok(domain, "A", selector, vals)

def check_aaaa(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "AAAA")
    if not ok:
        return [_row(domain, "AAAA", selector, "", err, "INFO")]
    return _ok(domain, "AAAA", selector, vals)

def check_ns(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "NS")
    if not ok:
        return [_row(domain, "NS", selector, "", err, "WARN")]
    sev = "OK" if len(vals) >= 2 else "WARN"
    issues = "" if sev=="OK" else "Single NS or resolution issue"
    return [_row(domain, "NS", selector, "; ".join(vals), issues, sev)]

def check_cname(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "CNAME")
    if not ok:
        return [_row(domain, "CNAME", selector, "", err, "INFO")]
    return _ok(domain, "CNAME", selector, vals)

def check_txt(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "TXT")
    if not ok:
        return [_row(domain, "TXT", selector, "", err, "INFO")]
    return _ok(domain, "TXT", selector, vals)

def check_soa(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "SOA")
    if not ok:
        return [_row(domain, "SOA", selector, "", err, "INFO")]
    return _ok(domain, "SOA", selector, vals)

def check_caa(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "CAA")
    if not ok:
        return [_row(domain, "CAA", selector, "", err, "INFO")]
    return _ok(domain, "CAA", selector, vals)

def check_srv(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "SRV")
    if not ok:
        return [_row(domain, "SRV", selector, "", err, "INFO")]
    return _ok(domain, "SRV", selector, vals)

def check_tlsa(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    ok, vals, err = q(domain, "TLSA")
    if not ok:
        return [_row(domain, "TLSA", selector, "", err, "INFO")]
    return _ok(domain, "TLSA", selector, vals)

def check_mta_sts(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    if not extended:
        return [_row(domain, "MTA-STS", selector, "", "Extended checks disabled", "INFO")]
    name = f"_mta-sts.{domain}"
    ok, vals, err = q(name, "TXT")
    if not ok:
        return [_row(domain, "MTA-STS", selector, "", "Missing TXT _mta-sts", "WARN")]
    txt = " ".join(vals)
    sev = "OK" if "v=STSv1" in txt and "id=" in txt else "WARN"
    issues = "" if sev=="OK" else "TXT should include v=STSv1; id=<id>"
    return [_row(domain, "MTA-STS", selector, txt, issues, sev)]

def check_tls_rpt(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    if not extended:
        return [_row(domain, "TLS-RPT", selector, "", "Extended checks disabled", "INFO")]
    name = f"_smtp._tls.{domain}"
    ok, vals, err = q(name, "TXT")
    if not ok:
        return [_row(domain, "TLS-RPT", selector, "", "Missing TXT _smtp._tls", "WARN")]
    txt = " ".join(vals)
    sev = "OK" if "v=TLSRPTv1" in txt and "rua=" in txt else "WARN"
    issues = "" if sev=="OK" else "TXT should include v=TLSRPTv1; rua=mailto:..."
    return [_row(domain, "TLS-RPT", selector, txt, issues, sev)]

def check_dnssec_info(domain: str, selector: str, q: QueryFunc, extended: bool=True):
    # Opportunistic: DNSKEY presence indicates potential DNSSEC
    ok, vals, err = q(domain, "DNSKEY")
    if ok and vals:
        return [_row(domain, "DNSSEC", selector, "DNSKEY present", "", "INFO")]
    else:
        return [_row(domain, "DNSSEC", selector, "", "No DNSKEY found (informational)", "INFO")]
