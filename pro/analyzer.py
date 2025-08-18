
"""
High-level Analyzer with concurrency, caching and pluggable checks.
This lives alongside your existing core, without removing any feature.
"""
from __future__ import annotations
import concurrent.futures as cf
from functools import lru_cache
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Iterable, Optional, Callable
import time

import dns.resolver
import dns.rdatatype
import pandas as pd

from .checks import REGISTRY

SEVERITY_ORDER = {"OK": 0, "INFO": 1, "WARN": 2, "CRITICAL": 3}

@dataclass
class AnalyzerConfig:
    nameservers: List[str] = field(default_factory=list)  # empty = system
    timeout: float = 3.0
    lifetime: float = 5.0
    max_workers: int = 16
    extended: bool = True  # enable extended checks (MTA‑STS, TLS‑RPT, etc.)

@dataclass
class Task:
    domain: str
    rtype: str
    selector: str = ""

def _mk_resolver(cfg: AnalyzerConfig) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    if cfg.nameservers:
        r.nameservers = cfg.nameservers
    r.timeout = cfg.timeout
    r.lifetime = cfg.lifetime
    return r

@lru_cache(maxsize=2048)
def _query_cached(qname: str, rtype: str, nameservers_key: str, timeout: float, lifetime: float) -> Tuple[bool, List[str], str]:
    """
    Cached raw query. Returns (ok, values, error)
    """
    res = dns.resolver.Resolver(configure=True)
    if nameservers_key:
        res.nameservers = nameservers_key.split(",")
    res.timeout = timeout
    res.lifetime = lifetime
    try:
        ans = res.resolve(qname, rtype)
        values = [str(r.to_text()) for r in ans]
        return True, values, ""
    except Exception as e:
        return False, [], f"{type(e).__name__}: {e}"

def normalize_domain(d: str) -> str:
    d = d.strip()
    if not d:
        return d
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        pass
    return d.lower().rstrip(".")

class DNSAnalyzerPro:
    def __init__(self, cfg: Optional[AnalyzerConfig] = None):
        self.cfg = cfg or AnalyzerConfig()

    def run(
        self,
        domains: Iterable[str],
        record_types: Iterable[str],
        selectors: Iterable[str] = (),
        progress_cb: Optional[Callable[[], None]] = None,
    ) -> pd.DataFrame:
        """
        Execute checks concurrently and return a DataFrame with
        columns: Domain, RecordType, Selector, Value, Issues, Severity.

        If *progress_cb* is provided it will be invoked after each task
        completes which allows callers to track progress.
        """
        domains = [normalize_domain(d) for d in domains if d.strip()]
        selectors = [s.strip() for s in selectors if s.strip()]
        rtypes = list(dict.fromkeys([rt.strip().upper() for rt in record_types]))

        tasks: List[Task] = []
        for d in domains:
            for rt in rtypes:
                if rt in ("DKIM","BIMI") and selectors:
                    for sel in selectors:
                        tasks.append(Task(d, rt, sel))
                else:
                    tasks.append(Task(d, rt))

        nameservers_key = ",".join(self.cfg.nameservers) if self.cfg.nameservers else ""
        results: List[Dict[str, str]] = []

        def _do(task: Task) -> List[Dict[str, str]]:
            func = REGISTRY.get(task.rtype)
            if not func:
                return [{
                    "Domain": task.domain, "RecordType": task.rtype, "Selector": task.selector,
                    "Value": "", "Issues": f"Record type not supported: {task.rtype}", "Severity": "INFO"
                }]
            resolver = _mk_resolver(self.cfg)
            def q(qname: str, rtype: str) -> Tuple[bool, List[str], str]:
                return _query_cached(qname, rtype, nameservers_key, self.cfg.timeout, self.cfg.lifetime)
            try:
                out = func(task.domain, task.selector, q, extended=self.cfg.extended)
                return out
            except Exception as e:
                return [{
                    "Domain": task.domain, "RecordType": task.rtype, "Selector": task.selector,
                    "Value": "", "Issues": f"Check error: {type(e).__name__}: {e}", "Severity": "CRITICAL"
                }]

        with cf.ThreadPoolExecutor(max_workers=self.cfg.max_workers) as ex:
            for chunk in _chunks(tasks, max(1, int(len(tasks)/(self.cfg.max_workers*2)) )):
                futures = [ex.submit(_do, t) for t in chunk]
                for fut in cf.as_completed(futures):
                    results.extend(fut.result())
                    if progress_cb:
                        progress_cb()

        df = pd.DataFrame(results, columns=["Domain","RecordType","Selector","Value","Issues","Severity"])
        # Order rows
        df["__sev"] = df["Severity"].map(SEVERITY_ORDER).fillna(99)
        df = df.sort_values(["Domain","RecordType","Selector","__sev"]).drop(columns="__sev")
        return df

def _chunks(lst, n):
    if n <= 0:
        n = 1
    for i in range(0, len(lst), n):
        yield lst[i:i+n]
