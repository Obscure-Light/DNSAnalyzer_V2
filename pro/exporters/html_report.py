
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape

def export_html(df, out_path: str):
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent.parent / "templates")),
        autoescape=select_autoescape()
    )
    tpl = env.get_template("report.html")
    sev_counts = df["Severity"].value_counts().to_dict()
    html = tpl.render(rows=df.to_dict(orient="records"), sev_counts=sev_counts)
    Path(out_path).write_text(html, encoding="utf-8")
    return out_path
