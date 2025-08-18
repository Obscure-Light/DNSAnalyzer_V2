
# DNS Analyzer – Pro Add‑on (non‑breaking)

This adds a modern table UI, plugin checks, concurrency, and HTML reporting **without removing** your original files.
You can continue using `main.py` and `gui.py` as before. New entry points:

- GUI Pro (Tkinter + Treeview):  
  ```bash
  python gui_pro.py
  ```
- CLI Pro:  
  ```bash
  python main_pro.py -d example.com -r SPF -r DMARC -r DKIM -s default -o out.html
  ```

## Highlights
- Concurrency with `ThreadPoolExecutor`
- Pluggable checks (`pro/checks/*.py`)
- Extended email security checks: SPF, DMARC, DKIM, BIMI, MTA‑STS, TLS‑RPT
- HTML report with severity badges
- Table UI: sorting, filtering, color‑coded severities, presets

## Notes
- PDF export can be done by printing the HTML report to PDF from your browser or system dialog.
- Optional nameservers via CLI `--nameserver 1.1.1.1 --nameserver 9.9.9.9`.

