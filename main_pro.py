
#!/usr/bin/env python3
import argparse, sys, json
import pandas as pd
from pro.analyzer import DNSAnalyzerPro, AnalyzerConfig
from pro.exporters.html_report import export_html

def main():
    ap = argparse.ArgumentParser(description="DNS Analyzer Pro – CLI (non-breaking: original CLI unchanged)")
    ap.add_argument("-d","--domain", action="append", help="Domain (repeatable)")
    ap.add_argument("-r","--record", action="append", help="Record type, e.g. A,MX,SPF,DMARC,DKIM,BIMI,MTA-STS,TLS-RPT,CAA")
    ap.add_argument("-s","--selector", action="append", default=[], help="Selector for DKIM/BIMI (repeatable)")
    ap.add_argument("--nameserver", action="append", default=[], help="Custom DNS server IP (repeatable)")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--lifetime", type=float, default=5.0)
    ap.add_argument("--no-extended", action="store_true", help="Disable extended checks (MTA-STS, TLS-RPT, DNSSEC info)")
    ap.add_argument("-o","--output", help="Output file (.csv|.json|.xlsx|.html)")
    args = ap.parse_args()

    if not args.domain or not args.record:
        ap.error("Provide at least one --domain and one --record")

    cfg = AnalyzerConfig(nameservers=args.nameserver, timeout=args.timeout, lifetime=args.lifetime, extended=not args.no_extended)
    analyzer = DNSAnalyzerPro(cfg)
    df = analyzer.run(args.domain, args.record, args.selector)

    if not args.output:
        print(df.to_string(index=False))
        return

    if args.output.endswith(".csv"):
        df.to_csv(args.output, index=False)
    elif args.output.endswith(".json"):
        df.to_json(args.output, orient="records", force_ascii=False, indent=2)
    elif args.output.endswith(".xlsx"):
        df.to_excel(args.output, index=False)
    elif args.output.endswith(".html"):
        export_html(df, args.output)
    else:
        sys.exit("Unknown output extension. Use .csv/.json/.xlsx/.html")
    print(f"Wrote {args.output}")

if __name__ == "__main__":
    main()
