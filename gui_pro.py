
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import pandas as pd
from pro.analyzer import DNSAnalyzerPro, AnalyzerConfig
from pro.checks import REGISTRY

RECORD_PRESETS = {
    "Email Security": ["SPF", "DMARC", "DKIM", "BIMI", "MX", "MTA-STS", "TLS-RPT", "CAA"],
    "Base DNS": ["A","AAAA","NS","SOA","CAA","MX","TXT"],
    "All": list(REGISTRY.keys()),
}

class DNSAnalyzerGUIPro(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        master.title("DNS Analyzer – Pro UI")
        master.geometry("1100x650")
        self.pack(fill="both", expand=True)

        self._build_controls()
        self._build_table()
        self._build_progress()

        self.analyzer = DNSAnalyzerPro()
        self.df = pd.DataFrame(columns=["Domain","RecordType","Selector","Value","Issues","Severity"])

    def _build_controls(self):
        top = ttk.Frame(self)
        top.pack(side="top", fill="x", padx=10, pady=8)

        ttk.Label(top, text="Domains (one per line):").grid(row=0, column=0, sticky="w")
        self.domains = tk.Text(top, width=50, height=5)
        self.domains.grid(row=1, column=0, padx=(0,8), pady=4, sticky="w")

        right = ttk.Frame(top); right.grid(row=1, column=1, sticky="nw")

        ttk.Label(right, text="Selectors (comma separated) for DKIM/BIMI:").grid(row=0, column=0, sticky="w")
        self.selectors_var = tk.StringVar(value="selector1, default")
        self.selectors = ttk.Entry(right, textvariable=self.selectors_var, width=40)
        self.selectors.grid(row=1, column=0, pady=(0,10), sticky="w")

        ttk.Label(right, text="Record types:").grid(row=2, column=0, sticky="w")
        records = sorted(RECORD_PRESETS["All"])
        self.record_vars = {
            rt: tk.BooleanVar(value=rt in RECORD_PRESETS["Email Security"])
            for rt in records
        }
        rec_frame = ttk.Frame(right); rec_frame.grid(row=3, column=0, sticky="w")
        for i, rt in enumerate(records):
            ttk.Checkbutton(rec_frame, text=rt, variable=self.record_vars[rt]).grid(
                row=i//4, column=i%4, sticky="w", padx=4, pady=2
            )

        btns = ttk.Frame(right); btns.grid(row=4, column=0, pady=6, sticky="w")
        ttk.Button(btns, text="Preset: Email Security", command=lambda: self._apply_preset("Email Security")).grid(row=0,column=0,padx=4)
        ttk.Button(btns, text="Preset: Base DNS", command=lambda: self._apply_preset("Base DNS")).grid(row=0,column=1,padx=4)
        ttk.Button(btns, text="Select All", command=lambda: self._apply_preset("All")).grid(row=0,column=2,padx=4)

        run_row = ttk.Frame(right); run_row.grid(row=5, column=0, pady=6, sticky="w")
        ttk.Button(run_row, text="Run", command=self.run_scan).grid(row=0, column=0, padx=(0,6))
        ttk.Button(run_row, text="Export CSV", command=lambda: self._export("csv")).grid(row=0,column=1, padx=4)
        ttk.Button(run_row, text="Export JSON", command=lambda: self._export("json")).grid(row=0,column=2, padx=4)
        ttk.Button(run_row, text="Export HTML", command=lambda: self._export("html")).grid(row=0,column=3, padx=4)
        ttk.Button(run_row, text="Export Excel", command=lambda: self._export("xlsx")).grid(row=0,column=4, padx=4)

    def _build_table(self):
        mid = ttk.Frame(self)
        mid.pack(side="top", fill="both", expand=True, padx=10, pady=8)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self._apply_filter())
        ttk.Label(mid, text="Filter:").pack(anchor="w")
        ttk.Entry(mid, textvariable=self.filter_var).pack(fill="x")

        cols = ("Domain","RecordType","Selector","Value","Issues","Severity")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c, command=lambda col=c: self._sort_by(col, False))
            self.tree.column(c, width=150 if c!="Value" else 400, anchor="w")
        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._style = ttk.Style()
        self._style.map("Treeview", background=[("selected", "#d0eaff")])

    def _build_progress(self):
        bottom = ttk.Frame(self)
        bottom.pack(side="bottom", fill="x", padx=10, pady=8)
        self.pbar = ttk.Progressbar(bottom, mode="determinate")
        self.pbar.pack(fill="x")

    def _apply_preset(self, name):
        targets = set(RECORD_PRESETS[name])
        for rt, var in self.record_vars.items():
            var.set(rt in targets)

    def _rows_from_df(self, df):
        for _, r in df.iterrows():
            values = [r[c] for c in ("Domain","RecordType","Selector","Value","Issues","Severity")]
            yield values

    def _render_df(self, df):
        self.tree.delete(*self.tree.get_children())
        for row in self._rows_from_df(df):
            tags = ("sev-"+row[-1],)
            self.tree.insert("", "end", values=row, tags=tags)
        # tag colors
        self.tree.tag_configure("sev-OK", background="#f7fff8")
        self.tree.tag_configure("sev-WARN", background="#fffdf2")
        self.tree.tag_configure("sev-CRITICAL", background="#fff7f7")

    def _apply_filter(self):
        q = self.filter_var.get().lower().strip()
        if not hasattr(self, "df"): return
        if not q:
            self._render_df(self.df); return
        mask = self.df.apply(lambda s: s.astype(str).str.lower().str.contains(q, na=False))
        filtered = self.df[mask.any(axis=1)]
        self._render_df(filtered)

    def _sort_by(self, col, descending):
        if not hasattr(self, "df"): return
        ascending = not descending
        self.df = self.df.sort_values(col, ascending=ascending)
        self._render_df(self.df)

    def update_ui(self, func, *args, **kwargs):
        """Execute `func` in the Tkinter main thread."""
        self.after(0, lambda: func(*args, **kwargs))

    def run_scan(self):
        doms = [d.strip() for d in self.domains.get("1.0","end").splitlines() if d.strip()]
        if not doms:
            messagebox.showerror("Input error", "Add at least one domain")
            return
        selectors = [s.strip() for s in self.selectors_var.get().split(",") if s.strip()]
        rtypes = [rt for rt,v in self.record_vars.items() if v.get()]
        if not rtypes:
            messagebox.showerror("Input error", "Select at least one record type")
            return

        # Progress bar (rough)
        total = len(doms) * sum( (len(selectors) if rt in ("DKIM","BIMI") and selectors else 1) for rt in rtypes )
        self.pbar["maximum"] = max(total, 1)
        self.pbar["value"] = 0

        self._render_df(pd.DataFrame(columns=["Domain","RecordType","Selector","Value","Issues","Severity"]))

        def progress():
            self.update_ui(lambda: self.pbar.step(1))

        def worker():
            cfg = AnalyzerConfig()
            analyzer = DNSAnalyzerPro(cfg)
            df = analyzer.run(doms, rtypes, selectors, progress_cb=progress)

            def finalize():
                self.df = df
                self._render_df(df)
                self.pbar["value"] = self.pbar["maximum"]

            self.update_ui(finalize)

        threading.Thread(target=worker, daemon=True).start()

    def _export(self, kind):
        if not hasattr(self, "df") or self.df.empty:
            messagebox.showinfo("Nothing to export", "Run a scan first")
            return
        if kind=="csv":
            path = filedialog.asksaveasfilename(defaultextension=".csv")
            if not path: return
            self.df.to_csv(path, index=False)
        elif kind=="json":
            path = filedialog.asksaveasfilename(defaultextension=".json")
            if not path: return
            self.df.to_json(path, orient="records", force_ascii=False, indent=2)
        elif kind=="html":
            path = filedialog.asksaveasfilename(defaultextension=".html")
            if not path: return
            from pro.exporters.html_report import export_html
            export_html(self.df, path)
        elif kind=="xlsx":
            path = filedialog.asksaveasfilename(defaultextension=".xlsx")
            if not path: return
            # use pandas basic export to keep deps light here
            self.df.to_excel(path, index=False)
        messagebox.showinfo("Export", f"Saved to {path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSAnalyzerGUIPro(root)
    root.mainloop()
