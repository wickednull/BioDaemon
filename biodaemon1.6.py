# file: biodaemon_v1.6.py
"""
BioDaemon v1.6
- Cyberpunk UI (Rich)
- Built-in configuration (plaintext JSON or encrypted vault)
- Headless --set / --set-secret for CI
- Async engine, modules, SQLite+FTS5, artifacts, NER
- Reports: HTML (PyVis), GEXF (Gephi), optional PDF (WeasyPrint)
- v1.5: Shodan host intel, Censys host intel, IP geolocation, Image EXIF → GPS, GeoMap
- NEW v1.6 (API-free additions):
    * Web Search (DuckDuckGo) — no API key
    * Dork Builder + Search (via DDG) — username/domain/email/phone dorks
    * Wayback Machine snapshots — CDX API
    * Expanded username coverage (FB/LinkedIn/YouTube/etc.)
"""

import sys
import subprocess
import json
import os
import logging
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import asyncio
import re
import argparse
from typing import Dict, Any, Callable, Optional, List, Tuple

# ---------- Dependency Management ----------
def ensure_deps():
    try:
        import aiohttp  # noqa
        import rich  # noqa
        import jinja2  # noqa
        import spacy  # noqa
        import networkx  # noqa
        import pyvis  # noqa
        import dnspython  # noqa
        import whois  # noqa
        from PIL import Image  # noqa
        import cryptography  # noqa
        import folium  # noqa
    except Exception:
        print("[*] Installing core dependencies (this may take a minute)...")
        pkgs = [
            "aiohttp", "rich", "jinja2", "spacy", "networkx", "pyvis",
            "dnspython", "python-whois", "Pillow", "tweepy", "praw",
            "vaderSentiment", "geopy", "folium", "weasyprint", "cryptography"
        ]
        subprocess.call([sys.executable, "-m", "pip", "install", *pkgs])

ensure_deps()

# Imports (after auto-install)
import aiohttp
from contextlib import asynccontextmanager
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from rich.align import Align
from jinja2 import Environment, select_autoescape
import whois
import dns.resolver
import spacy
import networkx as nx
from pyvis.network import Network
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken

# Optional libs
try:
    import tweepy
except Exception:
    tweepy = None

try:
    import praw
except Exception:
    praw = None

try:
    from weasyprint import HTML as WeasyHTML
except Exception:
    WeasyHTML = None

try:
    from playwright.async_api import async_playwright
except Exception:
    async_playwright = None

try:
    import folium
except Exception:
    folium = None

# ---------- Cyberpunk UI Theme ----------
CYBER_THEME = Theme({
    "primary": "#00FFC6",
    "accent": "#7DF9FF",
    "warn": "#FFD166",
    "bad": "#FF006E",
    "good": "#4AF626",
    "muted": "#8A8F98",
    "panel_border": "#5A32D1"
})
console = Console(theme=CYBER_THEME)

def neon_header(title: str, subtitle: str = ""):
    big = Text(title, style="primary bold")
    if subtitle:
        sub = Text(subtitle, style="accent")
        content = Align.center(Text.assemble(big, "\n", sub))
    else:
        content = Align.center(big)
    console.print(Panel(content, border_style="panel_border", title="[accent]BioDaemon[/accent]", subtitle="[muted]OSINT[/muted]"))

def neon_section(title: str):
    console.print(Panel(Text(title, style="accent bold"), border_style="panel_border"))

# ---------- Globals & Config ----------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
CONFIG_FILE = Path("credentials.json")
SECURE_FILE = Path("credentials.sec")
CASES_DIR = Path("cases")
REQUEST_TIMEOUT = 25
DEFAULT_UA = "BioDaemon/1.6"
REPORTS_DIRNAME = "reports"

# Expanded site list (API-free presence checks)
SITES_FOR_USERNAME_CHECK = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Bitbucket": "https://bitbucket.org/{}/",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}/",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Twitch": "https://www.twitch.tv/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
    "LinkedIn": "https://www.linkedin.com/in/{}/",
    "Facebook": "https://www.facebook.com/{}/",
    "Medium": "https://medium.com/@{}",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    "Keybase": "https://keybase.io/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Vimeo": "https://vimeo.com/{}"
}

# ---------- NLP (spaCy) ----------
def load_nlp():
    try:
        return spacy.load("en_core_web_trf")
    except Exception:
        try:
            return spacy.load("en_core_web_sm")
        except OSError:
            console.print(Panel("[bad]spaCy model not found. Installing 'en_core_web_sm'...[/bad]", border_style="bad"))
            subprocess.call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
            return spacy.load("en_core_web_sm")

nlp = load_nlp()

def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()

# ---------- Async HTTP with Backoff ----------
class Http:
    def __init__(self, ua: str = DEFAULT_UA, max_conn: int = 50, proxy: Optional[str] = None, use_browser: bool = False):
        self.ua = ua
        self.conn = aiohttp.TCPConnector(limit=max_conn)
        self.session: Optional[aiohttp.ClientSession] = None
        self.proxy = proxy
        self.use_browser = use_browser and async_playwright is not None
        self._browser_ctx = None

    @asynccontextmanager
    async def session_ctx(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=self.conn, headers={"User-Agent": self.ua})
        try:
            yield self.session
        finally:
            pass

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
        if self._browser_ctx:
            try:
                await self._browser_ctx.close()
            except Exception:
                pass
            self._browser_ctx = None

    async def get(self, url: str, timeout: int = REQUEST_TIMEOUT, allow_browser: bool = False) -> Tuple[int, str, str]:
        async with self.session_ctx() as s:
            try:
                async with s.get(url, proxy=self.proxy, timeout=timeout, allow_redirects=True) as r:
                    txt = await r.text(errors="ignore")
                    return r.status, txt, str(r.url)
            except Exception:
                if allow_browser and self.use_browser:
                    return await self._browser_fetch(url, timeout)
                raise

    async def head_or_get(self, url: str, timeout: int = REQUEST_TIMEOUT) -> int:
        async with self.session_ctx() as s:
            try:
                async with s.head(url, proxy=self.proxy, timeout=timeout, allow_redirects=True) as r:
                    return r.status
            except Exception:
                try:
                    async with s.get(url, proxy=self.proxy, timeout=timeout, allow_redirects=True) as r:
                        return r.status
                except Exception:
                    return -1

    async def _browser_fetch(self, url: str, timeout: int) -> Tuple[int, str, str]:
        if not self._browser_ctx:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            self._browser_ctx = await browser.new_context(user_agent=self.ua)
        page = await self._browser_ctx.new_page()
        try:
            resp = await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
            status = resp.status if resp else 0
            content = await page.content()
            final_url = page.url
            await page.close()
            return status, content, final_url
        except Exception:
            try:
                await page.close()
            except Exception:
                pass
            return 0, "", url

async def with_backoff(coro: Callable, max_tries=4, base=0.6):
    last_exc = None
    for i in range(max_tries):
        try:
            return await coro()
        except Exception as e:
            last_exc = e
            await asyncio.sleep(base * (2 ** i) + 0.2 * (i))
    if last_exc:
        raise last_exc

# ---------- Secure Config Helpers ----------
from base64 import urlsafe_b64encode
import hashlib

def _derive_key_from_password(password: str) -> bytes:
    return urlsafe_b64encode(hashlib.sha256(password.encode("utf-8")).digest())

def _load_secure_blob(password: str) -> dict:
    if not SECURE_FILE.exists():
        return {}
    key = _derive_key_from_password(password)
    f = Fernet(key)
    try:
        data = f.decrypt(SECURE_FILE.read_bytes())
        return json.loads(data.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError):
        raise ValueError("Invalid master password or corrupted vault.")

def _save_secure_blob(password: str, payload: dict):
    key = _derive_key_from_password(password)
    f = Fernet(key)
    data = json.dumps(payload, indent=2).encode("utf-8")
    SECURE_FILE.write_bytes(f.encrypt(data))

def _deep_set(obj: dict, dotted_path: str, value):
    cur = obj
    parts = dotted_path.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value

def merge_configs(plain: dict, secure: dict) -> dict:
    out = json.loads(json.dumps(plain or {}))
    def _merge(dst, src):
        for k, v in (src or {}).items():
            if isinstance(v, dict):
                _merge(dst.setdefault(k, {}), v)
            else:
                dst[k] = v
    _merge(out, secure or {})
    return out

def load_config() -> dict:
    plain = {}
    if CONFIG_FILE.exists():
        try:
            plain = json.load(open(CONFIG_FILE, "r", encoding="utf-8"))
        except Exception:
            console.print(Panel("[bad]credentials.json is malformed.[/bad]", border_style="bad"))
    secure = {}
    master_env = os.environ.get("BD_MASTER")
    if SECURE_FILE.exists() and master_env:
        try:
            secure = _load_secure_blob(master_env)
        except Exception as e:
            console.print(f"[warn]Secure vault could not be unlocked via BD_MASTER: {e}[/warn]")
    return merge_configs(plain, secure)

def configure_credentials():
    neon_section("Configuration")
    store = Prompt.ask("[accent]Storage type[/accent] (plain/encrypted)", choices=["plain", "encrypted"], default="encrypted")

    if store == "plain":
        cfg = {}
        if CONFIG_FILE.exists():
            try:
                cfg = json.load(open(CONFIG_FILE, "r", encoding="utf-8"))
            except Exception:
                cfg = {}
        while True:
            console.print("[muted]Enter dotted key (e.g., hibp.api_key) or 'done'[/muted]")
            path = Prompt.ask("Key path").strip()
            if path.lower() in ("done", "exit", "quit"):
                break
            val = Prompt.ask("Value (stored in plaintext)").strip()
            _deep_set(cfg, path, val)
            console.print(f"[good]Set {path}[/good]")
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        console.print(f"[good]Saved to {CONFIG_FILE}[/good]")
        return

    # encrypted
    if SECURE_FILE.exists():
        pw = getpass("Enter master password to unlock vault: ")
        try:
            vault = _load_secure_blob(pw)
        except Exception as e:
            console.print(f"[bad]{e}[/bad]"); return
    else:
        console.print("[accent]No vault found. Create a master password.[/accent]")
        while True:
            p1 = getpass("New master password: ")
            p2 = getpass("Confirm: ")
            if p1 and p1 == p2:
                break
            console.print("[warn]Passwords do not match. Try again.[/warn]")
        pw = p1
        vault = {}

    while True:
        console.print("[muted]Enter dotted key (e.g., twitter.api_key) or 'done'[/muted]")
        path = Prompt.ask("Key path").strip()
        if path.lower() in ("done", "exit", "quit"):
            break
        val = Prompt.ask("Value").strip()
        _deep_set(vault, path, val)
        console.print(f"[good]Set {path}[/good]")
    _save_secure_blob(pw, vault)
    console.print(f"[good]Encrypted vault saved to {SECURE_FILE}[/good]")
    console.print("[accent]Tip: export BD_MASTER to unlock in headless mode.[/accent]")

# ---------- Database (SQLite + FTS5) ----------
def init_database(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY,
        target_id INTEGER,
        module TEXT,
        timestamp TEXT,
        summary TEXT,
        raw_data TEXT,
        FOREIGN KEY(target_id) REFERENCES targets(id),
        UNIQUE(target_id, module)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY,
        type TEXT,
        value TEXT UNIQUE,
        source_module TEXT,
        first_seen TEXT,
        last_seen TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type)')
    try:
        c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(text, tokenize='porter')")
    except sqlite3.OperationalError:
        pass
    conn.commit()

def create_case(case_name: str, primary_target: str):
    CASES_DIR.mkdir(exist_ok=True)
    db_path = CASES_DIR / f"{case_name.replace(' ', '_').lower()}.db"
    if db_path.exists():
        console.print(f"[warn]Case '{case_name}' already exists.[/warn]")
        return None, None
    try:
        conn = sqlite3.connect(db_path)
        init_database(conn)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?, ?)", (primary_target, 'primary'))
        conn.commit()
        console.print(f"[good]✓ Case '{case_name}' created for target '{primary_target}'.[/good]")
        return conn, case_name
    except sqlite3.Error as e:
        console.print(f"[bad]DB error: {e}[/bad]")
        return None, None

def load_case(case_name: Optional[str] = None):
    CASES_DIR.mkdir(exist_ok=True)
    if case_name:
        db_path = CASES_DIR / f"{case_name.replace(' ', '_').lower()}.db"
        if not db_path.exists():
            console.print(f"[bad]Case '{case_name}' not found.[/bad]")
            return None, None
        try:
            conn = sqlite3.connect(db_path)
            console.print(f"[good]✓ Case '{case_name}' loaded.[/good]")
            return conn, case_name
        except sqlite3.Error as e:
            console.print(f"[bad]DB error: {e}[/bad]")
            return None, None

    cases = sorted([f for f in CASES_DIR.glob("*.db")])
    if not cases:
        console.print("[warn]No existing cases found.[/warn]")
        return None, None
    table = Table(title="Cases", title_style="accent")
    table.add_column("ID", style="primary")
    table.add_column("Case Name")
    table.add_column("Last Modified")
    for idx, case_path in enumerate(cases, 1):
        table.add_row(str(idx), case_path.stem, datetime.fromtimestamp(case_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'))
    console.print(table)
    choice = IntPrompt.ask("Select a case ID", choices=[str(i) for i in range(1, len(cases) + 1)])
    try:
        conn = sqlite3.connect(cases[choice - 1])
        console.print(f"[good]✓ Case '{cases[choice - 1].stem}' loaded.[/good]")
        return conn, cases[choice - 1].stem
    except sqlite3.Error as e:
        console.print(f"[bad]DB error: {e}[/bad]")
        return None, None

def get_primary_target(conn: sqlite3.Connection) -> str:
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    row = c.execute("SELECT name FROM targets WHERE type='primary' LIMIT 1").fetchone()
    return row['name'] if row else 'Unknown'

def save_result_to_db(conn: sqlite3.Connection, module: str, target_name: str, result: dict):
    c = conn.cursor()
    primary_exists = c.execute("SELECT id FROM targets WHERE type='primary'").fetchone() is not None
    c.execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?, ?)", (target_name, 'primary' if not primary_exists else 'secondary'))
    target_id = c.execute("SELECT id FROM targets WHERE name=?", (target_name,)).fetchone()[0]
    c.execute("""
        INSERT INTO results (target_id, module, timestamp, summary, raw_data)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(target_id, module) DO UPDATE SET
            timestamp=excluded.timestamp, summary=excluded.summary, raw_data=excluded.raw_data
    """, (target_id, module, utcnow_iso(), result.get('summary', ''), json.dumps(result.get('raw', {}))))
    conn.commit()

def ingest_text_fts(conn: sqlite3.Connection, text: str):
    if not text:
        return
    try:
        c = conn.cursor()
        c.execute("INSERT INTO notes_fts (text) VALUES (?)", (text,))
        conn.commit()
    except sqlite3.OperationalError:
        pass

def upsert_artifact(conn: sqlite3.Connection, a_type: str, value: str, source_module: str):
    c = conn.cursor()
    existing = c.execute("SELECT id FROM artifacts WHERE value=?", (value,)).fetchone()
    now = utcnow_iso()
    if existing:
        c.execute("UPDATE artifacts SET last_seen=? WHERE id=?", (now, existing[0]))
    else:
        c.execute("INSERT OR IGNORE INTO artifacts (type, value, source_module, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                  (a_type, value, source_module, now, now))
    conn.commit()

def get_all_case_results(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
        SELECT t.name as tname, r.module, r.summary, r.raw_data, r.timestamp
        FROM results r JOIN targets t ON r.target_id = t.id
        ORDER BY r.timestamp DESC
    """).fetchall()
    results = {}
    for row in rows:
        key = f"{row['module']}_{row['tname']}"
        if key not in results:
            results[key] = {
                "module": row['module'],
                "target": row['tname'],
                "summary": row['summary'],
                "raw": json.loads(row['raw_data']) if row['raw_data'] else None
            }
    return results

# ---------- Artifact Extraction ----------
ARTIFACT_PATTERNS = {
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "phone": r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}",
    "domain": r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url": r"https?://[^\s\"'>]+",
    "handle": r"(?<=\s|^|[@])@[A-Za-z0-9_]{2,30}"
}

def extract_artifacts(text: str) -> List[Tuple[str, str]]:
    found = []
    blob = text or ""
    for t, pat in ARTIFACT_PATTERNS.items():
        for m in re.findall(pat, blob, flags=re.I):
            v = m.strip()
            if t in ("email", "domain", "handle"):
                v = v.lower()
            found.append((t, v))
    return list({(t, v) for t, v in found})

def ingest_from_result(conn: sqlite3.Connection, module_key: str, result: dict):
    text_parts = []
    raw = result.get("raw") or {}
    def add_text(val):
        if isinstance(val, str):
            text_parts.append(val)
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str):
            add_text(x)
    walk(raw)
    text_all = "\n".join(text_parts)[:300000]
    ingest_text_fts(conn, text_all)
    for t, v in extract_artifacts(text_all):
        upsert_artifact(conn, t, v, module_key)

# ---------- EXIF helpers (GPS → lat/long) ----------
def _exif_get_gps(exif_named: dict):
    try:
        gps = exif_named.get("GPSInfo")
        if not gps:
            return None
        def conv(x):
            if isinstance(x, tuple) and len(x) == 2 and x[1]:
                return float(x[0]) / float(x[1])
            return float(x)
        lat_vals = gps.get(2); lat_ref = gps.get(1)
        lon_vals = gps.get(4); lon_ref = gps.get(3)
        if not (lat_vals and lon_vals and len(lat_vals) >= 3 and len(lon_vals) >= 3):
            return None
        lat = conv(lat_vals[0]) + conv(lat_vals[1]) / 60.0 + conv(lat_vals[2]) / 3600.0
        lon = conv(lon_vals[0]) + conv(lon_vals[1]) / 60.0 + conv(lon_vals[2]) / 3600.0
        if str(lat_ref).upper().startswith("S"): lat = -lat
        if str(lon_ref).upper().startswith("W"): lon = -lon
        return {"lat": lat, "lon": lon}
    except Exception:
        return None

# ---------- IP geolocation helper ----------
async def geolocate_ip(ip: str, config: dict, http: Http):
    token = (config.get("ipinfo") or {}).get("token")
    if token:
        url = f"https://ipinfo.io/{ip}?token={token}"
        try:
            async def req():
                status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
                if status == 200:
                    data = json.loads(text)
                    loc = data.get("loc")
                    if loc:
                        lat, lon = [float(x) for x in loc.split(",")]
                        return {"lat": lat, "lon": lon, "label": data.get("org") or data.get("city") or "ipinfo"}
                return None
            r = await with_backoff(req)
            if r: return r
        except Exception:
            pass
    # fallback: ip-api.com
    url = f"http://ip-api.com/json/{ip}"
    try:
        async def req2():
            status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
            if status == 200:
                data = json.loads(text)
                if data.get("status") == "success":
                    return {"lat": data.get("lat"), "lon": data.get("lon"), "label": data.get("org") or data.get("city") or "ip-api"}
            return None
        return await with_backoff(req2)
    except Exception:
        return None

# ---------- NER ----------
def apply_ner_analysis(results: dict):
    console.print(Text("\nPerforming Named Entity Recognition...", style="muted"))
    ner_results = {"PERSON": set(), "ORG": set(), "GPE": set(), "PRODUCT": set()}
    all_text = ""
    for data in results.values():
        raw = data.get("raw")
        if not raw:
            continue
        def walk(x):
            nonlocal all_text
            if isinstance(x, dict):
                for v in x.values():
                    walk(v)
            elif isinstance(x, list):
                for v in x:
                    walk(v)
            elif isinstance(x, str):
                all_text += " " + x
        walk(raw)
    if not all_text.strip():
        return {"summary": "No text found for NER.", "raw": {k: [] for k in ner_results}, "module": "NER Analysis", "target": "corpus"}
    doc = nlp(all_text)
    for ent in doc.ents:
        if ent.label_ in ner_results and len(ent.text.strip()) > 2:
            ner_results[ent.label_].add(ent.text.strip())
    for key in ner_results:
        ner_results[key] = sorted(list(ner_results[key]))
    return {
        "summary": f"Found {len(ner_results['PERSON'])} people, {len(ner_results['ORG'])} orgs, {len(ner_results['GPE'])} locations.",
        "raw": ner_results,
        "module": "NER Analysis",
        "target": "corpus"
    }

# ---------- Reporting ----------
def generate_interactive_graph(results: dict, primary_target: str, filename: str):
    net = Network(height="800px", width="100%", bgcolor="#0b0b14", font_color="#cdeaff", notebook=True)
    net.add_node(primary_target, color="#ff2bd1", size=25, title=f"Primary Target: {primary_target}")
    for key, data in results.items():
        if not data.get("raw") or key == "ner_analysis":
            continue
        module_name = data['module'].replace("_", " ").title()
        target_name = data['target']
        node_id = f"{module_name} ({target_name})"
        net.add_node(node_id, label=node_id, color="#00ffc6", size=15, title=data.get('summary'))
        base_node = primary_target if target_name == primary_target else target_name
        if base_node != node_id:
            net.add_edge(base_node, node_id, color="#7df9ff")
        if target_name != primary_target and not any(n.get('id') == target_name for n in net.nodes):
            net.add_node(target_name, color="#ffd166", size=20, title=f"Associated Target: {target_name}")
            net.add_edge(primary_target, target_name, color="#7df9ff")
    net.set_options('{"physics":{"barnesHut":{"gravitationalConstant":-40000,"centralGravity":0.4,"springLength":120}}}')
    net.save_graph(filename)

def export_gexf(results: dict, primary: str, out_path: str):
    g = nx.Graph()
    g.add_node(primary, kind="primary")
    for d in results.values():
        if not d.get("raw"):
            continue
        node = f"{d['module']}::{d['target']}"
        g.add_node(node, kind="module", summary=d.get("summary", ""))
        g.add_edge(primary if d['target'] == primary else d['target'], node)
    nx.write_gexf(g, out_path)

def generate_html_report(results: dict, primary_target: str, graph_file: str, out_html: str):
    HTML_TEMPLATE = """
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>BioDaemon Report: {{ target }}</title>
    <style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#0b0b14;color:#cdeaff;margin:0;padding:20px}
    h1,h2{color:#00ffc6;border-bottom:2px solid #5a32d1}
    a{color:#7df9ff}
    .container{max-width:1200px;margin:auto;background:#121225;padding:25px;border-radius:10px;box-shadow:0 0 24px rgba(0,0,0,.6)}
    .section{margin-bottom:30px;padding:20px;background:#16162d;border-left:5px solid #5a32d1;border-radius:6px}
    pre{background:#0e0e1a;padding:12px;border-radius:6px;white-space:pre-wrap;word-wrap:break-word;color:#a9c6ff}
    .graph-container{width:100%;height:650px;border:none;border-radius:6px}
    </style></head>
    <body><div class="container"><h1>BioDaemon OSINT Report: <span style="color:#ff2bd1">{{ target }}</span></h1><p>Generated: {{ timestamp }}</p>
    {% if results.ner_analysis %}<div class="section"><h2>Named Entity Recognition</h2><p>{{ results.ner_analysis.summary }}</p>
    {% for label, entities in results.ner_analysis.raw.items() if entities %}<h3>{{ label }}</h3><pre>{{ entities | join(', ') }}</pre>{% endfor %}</div>{% endif %}
    <div class="section"><h2>Relationship Graph</h2><iframe src="{{ graph_file }}" class="graph-container" frameborder="0"></iframe></div>
    {% for key, data in results.items() if key != 'ner_analysis' %}<div class="section"><h2>{{ data.module | replace('_', ' ') | title }} on '{{ data.target }}'</h2>
    <p><b>Summary:</b> {{ data.summary | replace('\\n', '<br>') | safe }}</p><h3>Raw Data:</h3><pre>{{ data.raw | tojson(indent=2) }}</pre></div>{% endfor %}
    </div></body></html>
    """
    env = Environment(autoescape=select_autoescape(['html']))
    template = env.from_string(HTML_TEMPLATE)
    rendered_html = template.render(
        target=primary_target,
        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        results=results,
        graph_file=Path(graph_file).name
    )
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(rendered_html)

def export_pdf_from_html(html_path: str, pdf_path: str):
    if WeasyHTML is None:
        return False, "WeasyPrint not installed"
    try:
        WeasyHTML(filename=html_path).write_pdf(pdf_path)
        return True, "ok"
    except Exception as e:
        return False, str(e)

def generate_geo_map_from_results(results: dict, out_html: str):
    if folium is None:
        return False, "folium not installed"
    markers = []
    for d in results.values():
        raw = d.get("raw") or {}
        geo = raw.get("geo")
        if isinstance(geo, dict) and isinstance(geo.get("lat"), (int,float)) and isinstance(geo.get("lon"), (int,float)):
            label = geo.get("label") or d.get("module")
            markers.append((geo["lat"], geo["lon"], f"{d.get('module')} / {d.get('target')} — {label}"))
    if not markers:
        return False, "no geo points"
    lat = sum(m[0] for m in markers) / len(markers)
    lon = sum(m[1] for m in markers) / len(markers)
    m = folium.Map(location=[lat, lon], zoom_start=2, tiles="CartoDB dark_matter")
    for la, lo, label in markers:
        folium.Marker([la, lo], popup=label).add_to(m)
    m.save(out_html)
    return True, "ok"

# ---------- Module System ----------
ModuleSpec = Dict[str, Any]
MODULES: Dict[str, ModuleSpec] = {}

def register_module(key: str, title: str, input_type: str):
    def deco(fn: Callable):
        MODULES[key] = {"key": key, "title": title, "input_type": input_type, "run": fn}
        return fn
    return deco

# -------- Core/Existing Modules --------
@register_module("username_check", "Username Availability", "username")
async def mod_username_check(target: str, config: dict, http: Http) -> dict:
    found = []
    async def check(name, url_fmt):
        url = url_fmt.format(target)
        status = await with_backoff(lambda: http.head_or_get(url))
        if status == 200:
            found.append({"site": name, "url": url})
    await asyncio.gather(*[check(name, fmt) for name, fmt in SITES_FOR_USERNAME_CHECK.items()])
    summary = f"Username '{target}' found on {len(found)} sites: {', '.join(s['site'] for s in found)}"
    return {"raw": {"found_on": found}, "summary": summary}

@register_module("domain_info", "Domain WHOIS/DNS", "domain")
async def mod_domain_info(target: str, config: dict, http: Http) -> dict:
    loop = asyncio.get_event_loop()
    def blocking_whois():
        try:
            return whois.whois(target)
        except Exception as e:
            return {"_error": str(e)}
    w = await loop.run_in_executor(None, blocking_whois)
    dns_records = {}
    for rt in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(target, rt)
            dns_records[rt] = [str(r) for r in answers]
        except Exception:
            dns_records[rt] = []
    if hasattr(w, "items"):
        whois_map = {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in w.items() if v}
    elif isinstance(w, dict):
        whois_map = w
    else:
        whois_map = {}
    raw = {"whois": whois_map, "dns": dns_records}
    registrar = (raw.get("whois") or {}).get("registrar", "N/A")
    summary = f"WHOIS for '{target}' found. Registrar: {registrar}."
    return {"raw": raw, "summary": summary}

@register_module("hibp_email", "HaveIBeenPwned", "email")
async def mod_hibp_email(target: str, config: dict, http: Http) -> dict:
    api_key = (config.get("hibp") or {}).get("api_key")
    if not api_key or not re.match(r"[^@]+@[^@]+\.[^@]+", target):
        return {"raw": None, "summary": "HIBP skipped (missing API key or invalid email)"}
    headers = {"hibp-api-key": api_key, "user-agent": "BioDaemon"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false"
    async def req():
        async with http.session_ctx() as s:
            async with s.get(url, headers=headers, proxy=http.proxy, timeout=REQUEST_TIMEOUT) as r:
                if r.status == 404:
                    return {"raw": None, "summary": f"[good]No breaches found for {target}.[/good]"}
                r.raise_for_status()
                data = await r.json()
                return {"raw": {"breaches": data}, "summary": f"[bad]Found in {len(data)} breaches.[/bad] Top 5: {', '.join(b['Name'] for b in data[:5])}"}
    try:
        return await with_backoff(req)
    except aiohttp.ClientResponseError as e:
        return {"raw": None, "summary": f"HIBP API error: {e.status}"}
    except Exception as e:
        return {"raw": None, "summary": f"HIBP error: {e}"}

@register_module("twitter", "Twitter", "username")
async def mod_twitter(target: str, config: dict, http: Http) -> dict:
    creds = (config.get("twitter") or {})
    if not tweepy or not creds:
        return {"raw": None, "summary": "Twitter skipped (missing tweepy or credentials)"}
    def blocking():
        try:
            client = tweepy.Client(
                bearer_token=creds.get("bearer_token"),
                consumer_key=creds.get("api_key"),
                consumer_secret=creds.get("api_secret"),
                access_token=creds.get("access_token"),
                access_token_secret=creds.get("access_secret"),
                wait_on_rate_limit=True
            )
            user_resp = client.get_user(username=target.lstrip("@"), user_fields=["public_metrics", "description", "location"])
            user_obj = user_resp.data
            if not user_obj:
                return {"raw": None, "summary": f"User {target} not found."}
            pm = user_obj.public_metrics or {}
            user_info = {
                "id": int(user_obj.id),
                "username": user_obj.username,
                "name": user_obj.name,
                "description": user_obj.description,
                "location": user_obj.location,
                "followers_count": pm.get("followers_count"),
                "following_count": pm.get("following_count"),
                "tweet_count": pm.get("tweet_count")
            }
            tweets_resp = client.get_users_tweets(id=user_obj.id, max_results=20, tweet_fields=["public_metrics", "created_at"])
            tweets = [{
                "id": int(t.id),
                "text": t.text,
                "retweets": (t.public_metrics or {}).get("retweet_count", 0),
                "likes": (t.public_metrics or {}).get("like_count", 0),
                "created_at": t.created_at.isoformat() if t.created_at else None
            } for t in (tweets_resp.data or [])]
            summary = f"@{user_info['username']} - Followers: {user_info['followers_count']}. Fetched {len(tweets)} tweets."
            return {"raw": {"user_info": user_info, "posted_tweets": tweets}, "summary": summary}
        except Exception as e:
            return {"raw": None, "summary": f"Twitter API error: {e}"}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, blocking)

@register_module("reddit", "Reddit", "username")
async def mod_reddit(target: str, config: dict, http: Http) -> dict:
    creds = (config.get("reddit") or {})
    if not praw or not all(creds.get(k) for k in ("client_id", "client_secret", "user_agent")):
        return {"raw": None, "summary": "Reddit skipped (missing praw or credentials)"}
    def blocking():
        try:
            r = praw.Reddit(client_id=creds["client_id"], client_secret=creds["client_secret"], user_agent=creds["user_agent"])
            user = r.redditor(target)
            comments = []
            for c in user.comments.new(limit=30):
                comments.append({
                    "subreddit": str(c.subreddit),
                    "score": c.score,
                    "created_utc": datetime.fromtimestamp(c.created_utc, tz=timezone.utc).isoformat(),
                    "body": c.body[:1000]
                })
            submissions = []
            for s in user.submissions.new(limit=15):
                submissions.append({
                    "subreddit": str(s.subreddit),
                    "score": s.score,
                    "created_utc": datetime.fromtimestamp(s.created_utc, tz=timezone.utc).isoformat(),
                    "title": s.title,
                    "url": s.url
                })
            summary = f"u/{target}: {len(submissions)} posts, {len(comments)} comments fetched."
            return {"raw": {"comments": comments, "submissions": submissions}, "summary": summary}
        except Exception as e:
            return {"raw": None, "summary": f"Reddit API error: {e}"}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, blocking)

# ---- v1.5 intel modules ----
@register_module("shodan_ip", "Shodan Host Intel", "ip")
async def mod_shodan_ip(target: str, config: dict, http: Http) -> dict:
    api_key = (config.get("shodan") or {}).get("api_key")
    if not api_key:
        return {"raw": None, "summary": "Shodan skipped (missing API key)"}
    url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
    async def req():
        status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
        if status == 200:
            data = json.loads(text)
            geo = None
            if isinstance(data.get("latitude"), (int,float)) and isinstance(data.get("longitude"), (int,float)):
                geo = {"lat": data["latitude"], "lon": data["longitude"], "label": data.get("org") or "Shodan"}
            return {"raw": {"host": data, "geo": geo}, "summary": f"Shodan: {target} | open ports: {len(data.get('ports', []))}"}
        return {"raw": None, "summary": f"Shodan error HTTP {status}"}
    try:
        return await with_backoff(req)
    except Exception as e:
        return {"raw": None, "summary": f"Shodan error: {e}"}

@register_module("censys_ip", "Censys Host Intel", "ip")
async def mod_censys_ip(target: str, config: dict, http: Http) -> dict:
    creds = (config.get("censys") or {})
    api_id, api_secret = creds.get("api_id"), creds.get("api_secret")
    if not (api_id and api_secret):
        return {"raw": None, "summary": "Censys skipped (missing api_id/api_secret)"}
    url = f"https://search.censys.io/api/v2/hosts/{target}"
    async def req():
        async with http.session_ctx() as s:
            auth = aiohttp.BasicAuth(api_id, api_secret)
            async with s.get(url, auth=auth, proxy=http.proxy, timeout=REQUEST_TIMEOUT) as r:
                if r.status == 200:
                    data = await r.json()
                    d = data.get("result") or {}
                    loc = d.get("location") or {}
                    geo = None
                    if isinstance(loc.get("latitude"), (int,float)) and isinstance(loc.get("longitude"), (int,float)):
                        geo = {"lat": loc["latitude"], "lon": loc["longitude"], "label": loc.get("city") or "Censys"}
                    return {"raw": {"host": d, "geo": geo}, "summary": f"Censys: {target} | services: {len(d.get('services', []))}"}
                return {"raw": None, "summary": f"Censys error HTTP {r.status}"}
    try:
        return await with_backoff(req)
    except Exception as e:
        return {"raw": None, "summary": f"Censys error: {e}"}

@register_module("geo_ip", "IP Geolocation", "ip")
async def mod_geo_ip(target: str, config: dict, http: Http) -> dict:
    info = await geolocate_ip(target, config, http)
    if not info:
        return {"raw": None, "summary": "GeoIP: no location found"}
    return {"raw": {"geo": info}, "summary": f"GeoIP: {target} → ({info['lat']:.4f}, {info['lon']:.4f})"}

@register_module("exif_image", "Image EXIF (GPS)", "path")
async def mod_exif_image(target: str, config: dict, http: Http) -> dict:
    try:
        from PIL import Image, ExifTags
    except Exception:
        return {"raw": None, "summary": "Pillow not installed"}
    p = Path(target)
    if not p.exists():
        return {"raw": None, "summary": f"File not found: {target}"}
    try:
        img = Image.open(str(p))
        exif = getattr(img, "_getexif", lambda: None)() or {}
        named = {}
        for k, v in (exif or {}).items():
            try:
                named[ExifTags.TAGS.get(k, k)] = v
            except Exception:
                named[k] = v
        gps = _exif_get_gps(named)
        raw = {"exif": named}
        if gps:
            raw["geo"] = gps
            summary = f"EXIF: GPS → ({gps['lat']:.6f}, {gps['lon']:.6f})"
        else:
            summary = "EXIF: no GPS found"
        return {"raw": raw, "summary": summary}
    except Exception as e:
        return {"raw": None, "summary": f"EXIF error: {e}"}

# ---- v1.6 API-free modules ----
@register_module("search_ddg", "Web Search (DuckDuckGo)", "query")
async def mod_search_ddg(target: str, config: dict, http: Http) -> dict:
    """
    API-free search via DuckDuckGo's HTML results.
    Input: free-text query (supports operators like site:, inurl:, filetype:)
    """
    import html as htmlmod
    q = target.strip()
    if not q:
        return {"raw": None, "summary": "DDG: empty query"}
    url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
    status, text, final = await http.get(url, timeout=REQUEST_TIMEOUT)
    if status != 200:
        return {"raw": None, "summary": f"DDG error HTTP {status}"}
    links = []
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', text, flags=re.I|re.S):
        href = htmlmod.unescape(m.group(1))
        title = re.sub("<.*?>", "", htmlmod.unescape(m.group(2))).strip()
        if href and title:
            links.append({"title": title[:200], "url": href})
        if len(links) >= 25:
            break
    summary = f"DDG: '{q}' → {len(links)} results (top {min(len(links),25)})"
    return {"raw": {"engine": "duckduckgo", "query": q, "results": links}, "summary": summary}

DORK_TEMPLATES = {
    "username": [
        'site:pastebin.com "{}"',
        'site:pastebin.com intext:"{}"',
        'site:github.com "{}"',
        'site:gitlab.com "{}"',
        '"{}" site:medium.com',
        '"{}" site:keybase.io',
        '"{}" filetype:pdf',
        '"{}" inurl:profile',
        '"{}" "email"'
    ],
    "domain": [
        'site:{} -www.{}',
        'site:pastebin.com "{}"',
        'inurl:{} "index of"',
        '"@{}" filetype:txt',
        '"@{}" filetype:csv',
        '"@{}" "password" -github',
        '"@{}" "confidential"'
    ],
    "email": [
        '"{}" -site:linkedin.com',
        '"{}" filetype:pdf',
        'site:pastebin.com "{}"'
    ],
    "phone": [
        '"{}" site:facebook.com',
        '"{}" site:twitter.com',
        '"{}" filetype:pdf'
    ]
}

@register_module("dork_search", "Dork Builder + Search (DDG)", "query")
async def mod_dork_search(target: str, config: dict, http: Http) -> dict:
    """
    Input format:
      username:the_handle
      domain:example.com
      email:user@example.com
      phone:+15551234567
    Builds common dorks and executes via DDG (no API keys).
    """
    if ":" not in target:
        return {"raw": None, "summary": "Dorks: use kind:value (username|domain|email|phone)"}
    kind, value = target.split(":", 1)
    kind = kind.strip().lower()
    value = value.strip()
    if kind not in DORK_TEMPLATES or not value:
        return {"raw": None, "summary": "Dorks: unsupported kind or empty value"}
    queries = [tpl.format(value) for tpl in DORK_TEMPLATES[kind]]
    results = []
    for q in queries:
        try:
            url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
            status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
            if status != 200:
                continue
            linkset = []
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', text, flags=re.I):
                href = m.group(1)
                if href and not any(href == x for x in linkset):
                    linkset.append(href)
                if len(linkset) >= 10:
                    break
            results.append({"query": q, "links": linkset})
        except Exception:
            pass
    summary = f"Dorks({kind}): built {len(queries)} queries; {sum(len(r['links']) for r in results)} links collected."
    return {"raw": {"kind": kind, "value": value, "queries": results}, "summary": summary}

@register_module("wayback", "Wayback Snapshots", "url")
async def mod_wayback(target: str, config: dict, http: Http) -> dict:
    """
    Input: domain or full URL (e.g., example.com or https://example.com)
    Uses the CDX API to list snapshot timestamps.
    """
    base = target.strip()
    if not base:
        return {"raw": None, "summary": "Wayback: empty input"}
    if not re.match(r"^https?://", base, re.I):
        qurl = f"http://{base}/*"
    else:
        qurl = base + ("/*" if not base.endswith("/*") else "")
    api = f"https://web.archive.org/cdx/search/cdx?url={aiohttp.helpers.quote(qurl, safe='')}&output=json&limit=50&fl=timestamp,original,statuscode,mimetype,length"
    status, text, _ = await http.get(api, timeout=REQUEST_TIMEOUT)
    if status != 200 or not text.strip():
        return {"raw": None, "summary": f"Wayback error HTTP {status}"}
    try:
        data = json.loads(text)
        if not data or len(data) <= 1:
            return {"raw": {"entries": []}, "summary": "Wayback: no snapshots"}
        headers, rows = data[0], data[1:]
        entries = []
        for row in rows[:200]:
            rec = dict(zip(headers, row))
            ts = rec.get("timestamp")
            rec["snapshot_url"] = f"https://web.archive.org/web/{ts}/{rec.get('original')}" if ts else None
            entries.append(rec)
        return {"raw": {"entries": entries}, "summary": f"Wayback: {len(entries)} snapshots"}
    except Exception:
        return {"raw": None, "summary": "Wayback: parse error"}

# ---------- Runner ----------
async def run_modules(conn: sqlite3.Connection, selections: List[Tuple[str, str]], config: dict, http: Http):
    tasks = []
    for mkey, targ in selections:
        mod = MODULES.get(mkey)
        if not mod or not targ:
            continue
        async def _run(m=mod, t=targ):
            try:
                res = await m["run"](t, config, http)
                if res and (res.get("raw") is not None or res.get("summary")):
                    save_result_to_db(conn, m["key"], t, res)
                    ingest_from_result(conn, m["key"], res)
                    console.print(f"[good]✓ {m['title']} finished:[/good] {res.get('summary','(no summary)')}")
                else:
                    console.print(f"[warn]• {m['title']} yielded no data.[/warn]")
            except Exception as e:
                console.print(f"[bad]✗ {m['title']} on '{t}' failed: {e}[/bad]")
        tasks.append(_run())
    if tasks:
        await asyncio.gather(*tasks)

# ---------- CLI / Interactive ----------
def capability_table(config: dict):
    table = Table(title="Capabilities", title_style="accent")
    table.add_column("Module/Feature", style="primary")
    table.add_column("Status")
    def ok(b): return "[good]enabled[/good]" if b else "[warn]limited[/warn]"
    table.add_row("Twitter", ok(tweepy and config.get("twitter")))
    table.add_row("Reddit", ok(praw and config.get("reddit") and all((config["reddit"].get(k) for k in ("client_id","client_secret","user_agent")))))
    table.add_row("HIBP", ok((config.get("hibp") or {}).get("api_key")))
    table.add_row("Shodan", ok((config.get("shodan") or {}).get("api_key")))
    table.add_row("Censys", ok((config.get("censys") or {}).get("api_id") and (config.get("censys") or {}).get("api_secret")))
    table.add_row("GeoIP (ipinfo)", ok((config.get("ipinfo") or {}).get("token")))
    table.add_row("Playwright", ok(async_playwright is not None))
    table.add_row("Folium (GeoMap)", ok(folium is not None))
    table.add_row("DDG Search / Dorks / Wayback", ok(True))
    console.print(table)

def show_artifacts(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT type, value, source_module, first_seen, last_seen FROM artifacts ORDER BY type, value").fetchall()
    if not rows:
        console.print("[warn]No artifacts stored yet.[/warn]")
        return
    table = Table(title="Artifacts", title_style="accent")
    table.add_column("Type", style="primary"); table.add_column("Value"); table.add_column("Source"); table.add_column("First Seen"); table.add_column("Last Seen")
    for r in rows:
        table.add_row(r["type"], r["value"], r["source_module"], r["first_seen"], r["last_seen"])
    console.print(table)

def make_reports(conn: sqlite3.Connection, case_name: str, report_kinds: Optional[List[str]] = None):
    console.print(Text("Gathering all case data for reporting...", style="muted"))
    results = get_all_case_results(conn)
    if not results:
        console.print("[warn]No results in case to report on.[/warn]")
        return
    ner = apply_ner_analysis(results)
    results_with_ner = dict(results)
    results_with_ner["ner_analysis"] = ner
    primary = get_primary_target(conn)

    ts = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    out_dir = CASES_DIR / case_name / REPORTS_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    graph_path = out_dir / f"graph_{case_name}_{ts}.html"
    html_path = out_dir / f"REPORT_{case_name.upper()}_{ts}.html"
    gexf_path = out_dir / f"graph_{case_name}_{ts}.gexf"
    pdf_path = out_dir / f"REPORT_{case_name.upper()}_{ts}.pdf"
    geo_map_path = out_dir / f"geomap_{case_name}_{ts}.html"

    generate_interactive_graph(results_with_ner, primary, str(graph_path))
    generate_html_report(results_with_ner, primary, str(graph_path), str(html_path))
    export_gexf(results_with_ner, primary, str(gexf_path))
    ok_map, why_map = generate_geo_map_from_results(results_with_ner, str(geo_map_path))

    msg = f"[good]✓ Reports saved:[/good]\n- HTML: {html_path}\n- Graph: {graph_path}\n- GEXF: {gexf_path}"
    if ok_map:
        msg += f"\n- GeoMap: {geo_map_path}"
    else:
        msg += f"\n- GeoMap: [warn]skipped ({why_map})[/warn]"
    if report_kinds and "pdf" in report_kinds:
        ok, why = export_pdf_from_html(str(html_path), str(pdf_path))
        if ok:
            msg += f"\n- PDF: {pdf_path}"
        else:
            msg += f"\n- PDF: [warn]skipped ({why})[/warn]"
    console.print(msg)

def interactive_menu(conn: sqlite3.Connection, case_name: str, config: dict):
    primary = get_primary_target(conn)
    capability_table(config)
    while True:
        neon_section(f"Case: {case_name}  |  Primary: {primary}")
        console.print("[primary]1.[/primary] Run Modules")
        console.print("[primary]2.[/primary] Generate Report")
        console.print("[primary]3.[/primary] Show Artifacts")
        console.print("[primary]4.[/primary] Configure Credentials")
        console.print("[primary]5.[/primary] Return to Main Menu")
        action = Prompt.ask("Select", choices=["1","2","3","4","5"], default="1")
        if action == "1":
            keys = list(MODULES.keys())
            table = Table(title="Available Modules", title_style="accent")
            table.add_column("ID", style="primary")
            table.add_column("Module")
            table.add_column("Input Type")
            for idx, k in enumerate(keys, 1):
                table.add_row(str(idx), MODULES[k]["title"], MODULES[k]["input_type"])
            console.print(table)
            raw_choice = Prompt.ask("Enter module IDs to run (e.g., 1,3,5)")
            try:
                ids = sorted({int(x.strip()) for x in raw_choice.split(",") if x.strip()})
            except Exception:
                console.print("[bad]Invalid selection.[/bad]")
                continue
            selections = []
            for i in ids:
                if 1 <= i <= len(keys):
                    k = keys[i - 1]
                    t = Prompt.ask(f"Target for {MODULES[k]['title']} ({MODULES[k]['input_type']})").strip()
                    selections.append((k, t))
            if not selections:
                console.print("[warn]No modules selected.[/warn]")
                continue
            http = Http(use_browser=False)
            try:
                asyncio.run(run_modules(conn, selections, config, http))
            finally:
                asyncio.run(http.close())
        elif action == "2":
            make_reports(conn, case_name)
        elif action == "3":
            show_artifacts(conn)
        elif action == "4":
            configure_credentials()
            config.update(load_config())
        else:
            break

# ---------- Headless ----------
def parse_args():
    ap = argparse.ArgumentParser(description="BioDaemon v1.6 OSINT")
    ap.add_argument("--headless", action="store_true", help="Run without interactive prompts")
    ap.add_argument("--new-case", type=str, help="Create a new case with this name")
    ap.add_argument("--load-case", type=str, help="Load an existing case with this name")
    ap.add_argument("--primary", type=str, help="Primary target name when creating a new case")
    ap.add_argument("--modules", type=str, help="Comma-separated module keys to run")
    # Inputs
    ap.add_argument("--username", type=str, help="Username for username_check/twitter/reddit")
    ap.add_argument("--domain", type=str, help="Domain for domain_info")
    ap.add_argument("--email", type=str, help="Email for hibp_email")
    ap.add_argument("--ip", type=str, help="IP address for shodan_ip/censys_ip/geo_ip")
    ap.add_argument("--path", type=str, help="File path for exif_image")
    ap.add_argument("--query", type=str, help="Query for search_ddg or dork_search (use kind:value for dork_search)")
    ap.add_argument("--url", type=str, help="URL or domain for wayback")
    # Network
    ap.add_argument("--proxy", type=str, help="HTTP/SOCKS proxy URL (e.g., socks5h://127.0.0.1:9050)")
    ap.add_argument("--use-browser", action="store_true", help="Use Playwright for JS pages when needed (if installed)")
    # Report
    ap.add_argument("--report", type=str, help="Comma-separated outputs: html,pdf,graph,gexf")
    # Config setters
    ap.add_argument("--set", action="append", help="Set plain credential key=value (e.g., hibp.api_key=XYZ)")
    ap.add_argument("--set-secret", action="append", help="Set encrypted credential key=value (requires BD_MASTER or prompt)")
    return ap.parse_args()

def build_selections_from_args(mod_list: List[str], args) -> List[Tuple[str, str]]:
    selections: List[Tuple[str, str]] = []
    for m in mod_list:
        spec = MODULES.get(m)
        if not spec:
            console.print(f"[warn]Unknown module '{m}' (skipping).[/warn]")
            continue
        itype = spec["input_type"]
        val = None
        if itype == "username":
            val = args.username
        elif itype == "domain":
            val = args.domain
        elif itype == "email":
            val = args.email
        elif itype == "ip":
            val = args.ip
        elif itype == "path":
            val = args.path
        elif itype == "query":
            val = args.query
        elif itype == "url":
            val = args.url
        if not val:
            console.print(f"[warn]Module '{m}' requires '{itype}' input (not provided) — skipping.[/warn]")
            continue
        selections.append((m, val))
    return selections

def headless_flow(args, config):
    # One-off config updates first
    if args.set:
        cfg = {}
        if CONFIG_FILE.exists():
            try: cfg = json.load(open(CONFIG_FILE,"r",encoding="utf-8"))
            except Exception: cfg = {}
        for item in args.set:
            if "=" in item:
                k, v = item.split("=",1)
                _deep_set(cfg, k.strip(), v.strip())
        with open(CONFIG_FILE,"w",encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        console.print(f("[good]Updated {CONFIG_FILE} via --set[/good]"))

    if args.set_secret:
        if SECURE_FILE.exists():
            pw = os.environ.get("BD_MASTER") or getpass("Master password: ")
            vault = _load_secure_blob(pw)
        else:
            pw = os.environ.get("BD_MASTER") or getpass("Create master password: ")
            vault = {}
        for item in args.set_secret:
            if "=" in item:
                k, v = item.split("=",1)
                _deep_set(vault, k.strip(), v.strip())
        _save_secure_blob(pw, vault)
        console.print(f"[good]Updated encrypted vault {SECURE_FILE} via --set-secret[/good]")

    # reload config after setters
    config.update(load_config())

    # Case handling
    conn, case_name = None, None
    if args.new_case:
        primary = args.primary or args.username or args.domain or args.email or args.ip or args.path or args.query or args.url or "primary"
        conn, case_name = create_case(args.new_case, primary)
    elif args.load_case:
        conn, case_name = load_case(args.load_case)
    else:
        console.print("[bad]Headless mode requires --new-case or --load-case.[/bad]")
        sys.exit(1)
    if not conn:
        sys.exit(1)

    # Modules
    mod_list = [m.strip() for m in (args.modules or "").split(",") if m.strip()]
    selections = build_selections_from_args(mod_list, args)
    if selections:
        http = Http(proxy=args.proxy, use_browser=args.use_browser)
        try:
            asyncio.run(run_modules(conn, selections, config, http))
        finally:
            asyncio.run(http.close())
    else:
        console.print("[warn]No runnable modules provided.[/warn]")

    # Reports
    report_kinds = [x.strip() for x in (args.report or "html,graph,gexf").split(",") if x.strip()]
    make_reports(conn, case_name, report_kinds)

# ---------- Main ----------
def main():
    neon_header("BioDaemon", "OSINT Analysis Platform v1.6 — Neon Mode")
    config = load_config()
    capability_table(config)

    args = parse_args()
    if args.headless:
        headless_flow(args, config)
        return

    conn, case_name = None, ""
    while True:
        if conn:
            conn.close()
        neon_section("Case Management")
        console.print("[primary]1.[/primary] Create New Case")
        console.print("[primary]2.[/primary] Load Existing Case")
        console.print("[primary]3.[/primary] Configure Credentials")
        console.print("[primary]0.[/primary] Exit")
        choice = Prompt.ask("Select", choices=["1","2","3","0"], default="1")
        if choice == "1":
            case_name_input = Prompt.ask("Case name").strip()
            if case_name_input:
                primary_target_input = Prompt.ask(f"Primary target for '{case_name_input}'").strip()
                if primary_target_input:
                    conn, case_name = create_case(case_name_input, primary_target_input)
        elif choice == "2":
            conn, case_name = load_case()
        elif choice == "3":
            configure_credentials()
            config.update(load_config())
            continue
        else:
            sys.exit(0)

        if conn:
            try:
                interactive_menu(conn, case_name, config)
            finally:
                if conn:
                    conn.close()

if __name__ == "__main__":
    main()