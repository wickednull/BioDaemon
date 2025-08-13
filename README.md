# BioDaemon
BioDaemon is a covert OSINT intelligence platform for deep digital footprint analysis. It uses a persistent database to manage investigation cases, correlating data from social media, domains, and data breaches. Its analysis engine automatically extracts key entities and visualizes hidden connections in a final interactive report.

![image](https://github.com/user-attachments/assets/24760a36-8fab-4eef-9891-03e645400f10)

</div>
<p align="center">
<strong>OSINT Analysis Platform v1.0</strong>
</p>
<p align="center">
<img alt="Python Version" src="https://img.shields.io/badge/python-3.9%2B-blue.svg">
<img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg">
<img alt="Status" src="https://img.shields.io/badge/status-development-orange.svg">
</p>
> BioDaemon is a covert OSINT intelligence platform for deep digital footprint analysis. It uses a persistent database to manage investigation cases, correlating data from social media, domains, and data breaches. Its analysis engine automatically extracts key entities and visualizes hidden connections in a final interactive report.

# BioDaemon v1.3 — OSINT Casework Toolkit

Single-file OSINT platform with async fetchers, case management (SQLite + FTS5), NER (spaCy), artifact extraction, interactive HTML reports (PyVis), and Gephi export (GEXF). Optional PDF export (WeasyPrint) and JS-rendering (Playwright).

FEATURES:
- Async HTTP engine (aiohttp) with exponential backoff
- Pluggable in-file modules: username check, WHOIS/DNS, HIBP, Twitter, Reddit
- Case database (SQLite), artifacts table, and FTS5 full-text search
- spaCy NER (auto-uses en_core_web_trf if installed; falls back to sm)
- Interactive Rich UI and headless CLI mode
- Reports: HTML (with interactive graph), GEXF (Gephi), optional PDF

--------------------------------------------------
QUICK START (Linux/macOS)
--------------------------------------------------
1) Get the code
git clone https://github.com/wickednull/BioDaemon.git
cd BioDaemon

2) Make a Python virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

3) Install dependencies
pip install -U pip setuptools wheel
pip install aiohttp rich jinja2 spacy networkx pyvis dnspython python-whois tweepy praw vaderSentiment geopy folium

Optional (PDF export)
pip install weasyprint

Optional (JS sites / anti-bot pages)
pip install playwright
playwright install chromium

4) Download the spaCy model
python -m spacy download en_core_web_sm

5) Run (interactive)
python biodaemon_v1.3.py

NOTE: Do not use `sudo python …` inside a venv. It bypasses your venv and triggers Debian’s PEP 668 lock.

--------------------------------------------------
QUICK START (Windows 10/11 PowerShell)
--------------------------------------------------
git clone https://github.com/wickednull/BioDaemon.git
cd BioDaemon

py -m venv venv
.\venv\Scripts\Activate.ps1

pip install -U pip setuptools wheel
pip install aiohttp rich jinja2 spacy networkx pyvis dnspython python-whois tweepy praw vaderSentiment geopy folium
python -m spacy download en_core_web_sm

py biodaemon_v1.3.py

WeasyPrint and Playwright are optional on Windows; they may require extra native libs/browsers.

--------------------------------------------------
SYSTEM REQUIREMENTS
--------------------------------------------------
- Python 3.10+
- SQLite (bundled with Python)
- Internet connectivity for API queries and JS rendering (if used)

Debian/Ubuntu/Kali extras (recommended):
sudo apt update
sudo apt install -y python3-venv build-essential pkg-config libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
# Optional WeasyPrint system libs (for PDF export)
sudo apt install -y libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi8

--------------------------------------------------
CONFIG: credentials.json
--------------------------------------------------
Place this file next to biodaemon_v1.3.py. Missing keys disable the module.

{
  "hibp": { "api_key": "YOUR_HIBP_API_KEY" },
  "twitter": {
    "api_key": "TW_API_KEY",
    "api_secret": "TW_API_SECRET",
    "bearer_token": "TW_BEARER",
    "access_token": "TW_ACCESS",
    "access_secret": "TW_ACCESS_SECRET"
  },
  "reddit": {
    "client_id": "REDDIT_CLIENT_ID",
    "client_secret": "REDDIT_CLIENT_SECRET",
    "user_agent": "BioDaemon/1.3 by <you>"
  }
}

--------------------------------------------------
USAGE
--------------------------------------------------
Interactive mode:
source venv/bin/activate
python biodaemon_v1.3.py

Headless (CI/cron) example:
# New case, run username_check + domain_info
python biodaemon_v1.3.py --headless \
  --new-case "Acme_Investigation" --primary "acme_corp" \
  --modules username_check,domain_info \
  --username acmec0rp --domain example.com \
  --report html,graph,gexf

# Existing case, run HIBP (requires credentials.json)
python biodaemon_v1.3.py --headless \
  --load-case "Acme_Investigation" \
  --modules hibp_email --email user@example.com \
  --report html,pdf,graph,gexf

CLI flags:
--headless — non-interactive run
--new-case <name> / --load-case <name>
--primary <target> — primary target for new case
--modules <k1,k2,...> — module keys (see below)
--username <val> / --domain <val> / --email <val> — per-module inputs
--proxy <url> — e.g. socks5h://127.0.0.1:9050
--use-browser — enable Playwright for JS pages (if installed)
--report <list> — any of html,pdf,graph,gexf

--------------------------------------------------
MODULES (keys)
--------------------------------------------------
username_check — Checks popular sites for a handle
domain_info — WHOIS + DNS (A/MX/TXT/NS)
hibp_email — HaveIBeenPwned (needs API key)
twitter — Fetches public profile + recent tweets (needs creds)
reddit — Fetches recent posts/comments (needs creds)

Reports saved to: cases/<CASE_NAME>/reports/

--------------------------------------------------
COMMON ISSUES & FIXES
--------------------------------------------------
1) "externally-managed-environment"
Use a venv (see Quick Start) or:
pip install --break-system-packages <pkg> (not recommended)

2) "ModuleNotFoundError: whois"
`apt install whois` installs CLI, not Python lib.
Fix: pip install python-whois

3) spaCy model missing
python -m spacy download en_core_web_sm

4) Playwright says browsers not installed
pip install playwright
playwright install chromium

5) PDF export fails
Install Debian extras or skip PDF.

6) "Nothing happens with sudo"
Don’t run sudo inside venv.
If needed: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

--------------------------------------------------
UPDATING
--------------------------------------------------
git pull
source venv/bin/activate
pip install -U aiohttp rich jinja2 spacy networkx pyvis dnspython python-whois tweepy praw vaderSentiment geopy folium weasyprint
python -m spacy download en_core_web_sm

--------------------------------------------------
VERIFY INSTALLATION
--------------------------------------------------
source venv/bin/activate
python - <<'PY'
import whois, spacy, aiohttp, rich, networkx, dns.resolver, jinja2, pyvis
print("BioDaemon deps OK")
PY

--------------------------------------------------
LICENSE
--------------------------------------------------
MIT 

--------------------------------------------------
DISCLAIMER
--------------------------------------------------
For educational and defensive security research in environments where you have explicit permission.
