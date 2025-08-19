import os
import sys
import base64
from unittest.mock import Mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pro.checks.spf import check_spf
from pro.checks.dmarc import check_dmarc
from pro.checks.dkim import check_dkim
from pro.checks.bimi import check_bimi
from pro.checks.mx import check_mx


def make_query(records):
    def _query(name, qtype):
        return records.get((name, qtype), (False, [], "NXDOMAIN"))
    return Mock(side_effect=_query)


def test_check_spf_success():
    q = make_query({("example.com", "TXT"): (True, ["v=spf1 -all"], "")})
    row = check_spf("example.com", "", q)[0]
    assert row["Severity"] == "OK"
    assert row["Issues"] == ""


def test_check_spf_missing():
    q = make_query({("example.com", "TXT"): (True, ["no spf"], "")})
    row = check_spf("example.com", "", q)[0]
    assert row["Severity"] == "WARN"
    assert row["Issues"] == "No SPF record found"


def test_check_dmarc_success():
    q = make_query({("_dmarc.example.com", "TXT"): (True, ["v=DMARC1; p=reject; rua=mailto:agg@example.com; adkim=s; aspf=s"], "")})
    row = check_dmarc("example.com", "", q)[0]
    assert row["Severity"] == "OK"
    assert row["Issues"] == ""


def test_check_dmarc_missing():
    q = make_query({("_dmarc.example.com", "TXT"): (False, [], "err")})
    row = check_dmarc("example.com", "", q)[0]
    assert row["Severity"] == "CRITICAL"
    assert row["Issues"] == "DMARC record not found"


def test_check_dkim_success():
    key = base64.b64encode(b"0" * 256).decode()
    q = make_query({("default._domainkey.example.com", "TXT"): (True, [f"v=DKIM1; p={key}"], "")})
    row = check_dkim("example.com", "", q)[0]
    assert row["Severity"] == "OK"
    assert row["Issues"] == ""


def test_check_dkim_missing():
    q = make_query({})
    row = check_dkim("example.com", "selector", q)[0]
    assert row["Severity"] == "CRITICAL"
    assert row["Issues"] == "DKIM selector not found"


def test_check_bimi_success():
    q = make_query({("default._bimi.example.com", "TXT"): (True, ["v=BIMI1; l=https://logo.example.com/logo.svg; a=https://logo.example.com/vmc.pem"], "")})
    row = check_bimi("example.com", "", q)[0]
    assert row["Severity"] == "OK"
    assert row["Issues"] == ""


def test_check_bimi_missing():
    q = make_query({})
    row = check_bimi("example.com", "", q)[0]
    assert row["Severity"] == "INFO"
    assert row["Issues"] == "BIMI record not found"


def test_check_mx_success():
    q = make_query({("example.com", "MX"): (True, ["10 mail1.example.com.", "20 mail2.example.com."], "")})
    row = check_mx("example.com", "", q)[0]
    assert row["Severity"] == "OK"
    assert row["Issues"] == ""


def test_check_mx_missing():
    q = make_query({("example.com", "MX"): (False, [], "err")})
    row = check_mx("example.com", "", q)[0]
    assert row["Severity"] == "CRITICAL"
    assert row["Issues"] == "No MX"
