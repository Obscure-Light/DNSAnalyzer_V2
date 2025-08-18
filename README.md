# DNS Analyzer – Core & Pro

Strumento per l’analisi DNS focalizzato sulla **security della posta** (SPF, DMARC, DKIM, BIMI, MX) e sui record base (A/AAAA/NS/SOA/CAA/TXT), con export in vari formati.  
La **versione Pro** aggiunge UI tabellare moderna, **report HTML**, controlli estesi (MTA-STS, TLS-RPT, DNSSEC info), parallelismo e architettura a **plugin**.

> ✅ Niente è stato rimosso: puoi continuare ad usare `main.py`, `gui.py` e l’export esistente.  
> ✨ In più trovi `gui_pro.py` e `main_pro.py` con le funzionalità avanzate.

---

## Requisiti
- **Python 3.9+**
- Dipendenze principali (vedi `requirements.txt`):
  - `dnspython`, `pandas`, `openpyxl`
  - **Pro**: `Jinja2`

Installa tutto con:
```bash
pip install -r requirements.txt
```

---

## Come si usa (Core)

### CLI core
```bash
python main.py -d example.com -r SPF -r DMARC
```

### GUI core
```bash
python gui.py
```

---

## Come si usa (Pro)

### GUI Pro
Interfaccia tabellare con **sort**, **filtro**, **color-coding severità**, **preset** e progress bar.

```bash
python gui_pro.py
```

Caratteristiche principali:
- Campi “Domains” (uno per riga) e “Selectors” (per DKIM/BIMI, separati da virgola)
- CheckBox per i record; **preset**: “Email Security”, “Base DNS”, “Select All”
- Tabella con colonne: Domain, RecordType, Selector, Value, Issues, Severity
- **Filtro** in tempo reale
- **Export**: CSV / JSON / HTML / XLSX

### CLI Pro
```bash
python main_pro.py   -d example.com -d example.org   -r SPF -r DMARC -r DKIM -r BIMI -r MX -r MTA-STS -r TLS-RPT -r CAA -r A -r AAAA -r NS -r SOA   -s default -s selector1   --nameserver 1.1.1.1 --nameserver 9.9.9.9   -o report.html
```

Opzioni principali:
- `-d/--domain`: dominio (ripetibile)
- `-r/--record`: record da analizzare (ripetibile)
- `-s/--selector`: selector per DKIM/BIMI (ripetibile)
- `--nameserver`: resolver DNS custom (ripetibile)
- `--timeout`, `--lifetime`: timeout dnspython
- `--no-extended`: disattiva controlli estesi Pro
- `-o/--output`: scrive `.csv | .json | .xlsx | .html`

---

## Funzionalità principali
- Analisi DNS per più domini e più record
- **Email Security**: SPF, DMARC, DKIM, BIMI, MX
- **Base DNS**: A/AAAA/NS/SOA/CAA/TXT
- Esportazioni: CSV, JSON, Excel; **Pro**: anche **HTML**
- **Pro**:
  - Architettura a **plugin** (`pro/checks/*.py`) – facile da estendere
  - **Parallelismo** con ThreadPool + cache LRU
  - UI moderna tabellare (Tkinter/Treeview)
  - Controlli estesi: **MTA-STS**, **TLS-RPT**, info **DNSSEC**
  - Normalizzazione domini (IDNA/punycode), dedup, gestione errori esplicita

---

## Controlli implementati

### SPF
- Parsing di `v=spf1`
- Calcolo **lookup count** (RFC 7208) su `include`, `a`, `mx`, `ptr`, `exists`, `redirect`  
  → `>10` ⇒ **CRITICAL**
- Rilevazione `+all`/`all` permissivo, mancanza di `all`
- Record multipli ⇒ **CRITICAL**

### DMARC (`_dmarc.<dominio>`)
- Parsing chiavi `p`, `rua`, `pct`, `adkim`, `aspf`, `sp`
- `p=none` ⇒ **WARN** (o **CRITICAL** se assente)
- `rua` mancante ⇒ **WARN**
- Allineamento suggerito `adkim=s`, `aspf=s`

### DKIM (`<selector>._domainkey.<dominio>`)
- Parsing `p=` e **stima bit-length** chiave
- `<1024` ⇒ **CRITICAL**, `<2048` ⇒ **WARN**
- Flag `t=y` ⇒ **WARN**

### BIMI (`<selector>._bimi.<dominio>`)
- Verifica `l=` (SVG logo URL) e `a=` (VMC)
- Mancanza ⇒ WARN/INFO

### MX
- Ridondanza server: **single MX** ⇒ WARN
- Normalizzazione host/priorità

### MTA-STS (`_mta-sts.<dom>`)
- TXT con `v=STSv1` e `id=…`

### TLS-RPT (`_smtp._tls.<dom>`)
- TXT con `v=TLSRPTv1` e `rua=mailto:…`

### DNSSEC
- Presenza record `DNSKEY` ⇒ INFO

### Base DNS
- **A/AAAA**: esistenza indirizzi
- **NS**: ≥2 ⇒ OK, 1 ⇒ WARN
- **SOA/CAA/TXT/CNAME**: esistenza e validità

---

## Plugin esterni

DNS Analyzer può essere esteso con plugin che registrano nuovi controlli
tramite l'entry point `dns_analyzer.checks`.

### setup.py
```python
from setuptools import setup

setup(
    # ...
    entry_points={
        "dns_analyzer.checks": [
            "CUSTOM=my_plugin:check_custom",
        ],
    },
)
```

### pyproject.toml
```toml
[project.entry-points."dns_analyzer.checks"]
CUSTOM = "my_plugin:check_custom"
```
