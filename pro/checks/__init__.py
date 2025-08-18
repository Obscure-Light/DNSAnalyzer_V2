
from .spf import check_spf
from .dmarc import check_dmarc
from .dkim import check_dkim
from .bimi import check_bimi
from .mx import check_mx
from .base import (
    check_a, check_aaaa, check_ns, check_cname, check_txt, check_soa, check_caa,
    check_mta_sts, check_tls_rpt, check_dnssec_info
)
REGISTRY = {
    "A": check_a,
    "AAAA": check_aaaa,
    "MX": check_mx,
    "NS": check_ns,
    "CNAME": check_cname,
    "TXT": check_txt,
    "SOA": check_soa,
    "CAA": check_caa,
    "SPF": check_spf,
    "DMARC": check_dmarc,
    "DKIM": check_dkim,  # requires selectors list
    "BIMI": check_bimi,  # requires selectors list (default, if not provided)
    "MTA-STS": check_mta_sts,
    "TLS-RPT": check_tls_rpt,
    "DNSSEC": check_dnssec_info,
}
