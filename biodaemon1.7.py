# file: biodaemon_v1.7.1.py
"""
BioDaemon v1.7.1
- Cyberpunk UI (Rich), case DB (SQLite+FTS5), artifacts, NER
- Reports: HTML (PyVis), GEXF, optional PDF (WeasyPrint), GeoMap (Folium)

v1.5: Shodan, Censys, GeoIP, EXIF→GPS
v1.6: API-free DDG search, Dork Builder + Search, Wayback, expanded username checks
v1.7: No-API recon: phone_osint, email_osint, image_reverse (free), linkedin_search
v1.7.1: + GitHub dorking (no API), Pastebin search (no API), optional API for image reverse

LAW & ETHICS: Use only with explicit authorization. You are responsible for compliance with all laws.
"""

import sys, subprocess, json, os, logging, sqlite3, asyncio, re, argparse, hashlib, mimetypes, io
from pathlib import Path
from datetime import datetime, timezone
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
        import phonenumbers  # noqa
        import imagehash  # noqa
    except Exception:
        print("[*] Installing core dependencies (this may take a minute)...")
        pkgs = [
            "aiohttp", "rich", "jinja2", "spacy", "networkx", "pyvis",
            "dnspython", "python-whois", "Pillow", "tweepy", "praw",
            "vaderSentiment", "geopy", "folium", "weasyprint", "cryptography",
            "phonenumbers", "ImageHash"
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
import whois, dns.resolver, spacy, networkx as nx
from pyvis.network import Network
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken

# Optional libs
try: import tweepy
except Exception: tweepy = None
try: import praw
except Exception: praw = None
try:
    from weasyprint import HTML as WeasyHTML
except Exception: WeasyHTML = None
try: import folium
except Exception: folium = None
try: import phonenumbers
except Exception: phonenumbers = None
try:
    from PIL import Image, ExifTags
except Exception:
    Image = None; ExifTags = None
try: import imagehash as _imagehash
except Exception: _imagehash = None

# ---------- Cyberpunk UI Theme (embedded) ----------
CYBER_THEME = Theme({
    "primary": "#00FFC6",   # neon mint
    "accent":  "#7DF9FF",   # neon blue
    "warn":    "#FFD166",   # honey
    "bad":     "#FF006E",   # neon magenta/red
    "good":    "#4AF626",   # CRT green
    "muted":   "#8A8F98",   # gray
    "panel_border": "#5A32D1"  # purple neon
})
console = Console(theme=CYBER_THEME)

def neon_header(title: str, subtitle: str = ""):
    big = Text(title, style="primary bold")
    content = Align.center(Text.assemble(big, "\n", Text(subtitle, style="accent")) if subtitle else big)
    console.print(Panel(content, border_style="panel_border", title="[accent]BioDaemon[/accent]", subtitle="[muted]OSINT[/muted]"))

def neon_section(title: str):
    console.print(Panel(Text(title, style="accent bold"), border_style="panel_border"))

# ---------- Globals & Config ----------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
CONFIG_FILE = Path("credentials.json")
SECURE_FILE = Path("credentials.sec")
CASES_DIR = Path("cases")
REQUEST_TIMEOUT = 25
DEFAULT_UA = "BioDaemon/1.7.1"
REPORTS_DIRNAME = "reports"

# Expanded site list for username presence checks
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
    try: return spacy.load("en_core_web_trf")
    except Exception:
        try: return spacy.load("en_core_web_sm")
        except OSError:
            console.print(Panel("[bad]spaCy model not found. Installing 'en_core_web_sm'...[/bad]", border_style="bad"))
            subprocess.call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
            return spacy.load("en_core_web_sm")
nlp = load_nlp()

def utcnow_iso(): return datetime.now(timezone.utc).isoformat()

# ---------- Async HTTP with Backoff ----------
class Http:
    def __init__(self, ua: str = DEFAULT_UA, max_conn: int = 50, proxy: Optional[str] = None):
        self.ua = ua
        self.conn = aiohttp.TCPConnector(limit=max_conn)
        self.session: Optional[aiohttp.ClientSession] = None
        self.proxy = proxy

    @asynccontextmanager
    async def session_ctx(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=self.conn, headers={"User-Agent": self.ua})
        try:
            yield self.session
        finally:
            pass

    async def close(self):
        if self.session: await self.session.close(); self.session = None

    async def get(self, url: str, timeout: int = REQUEST_TIMEOUT) -> Tuple[int, str, str]:
        async with self.session_ctx() as s:
            async with s.get(url, proxy=self.proxy, timeout=timeout, allow_redirects=True) as r:
                txt = await r.text(errors="ignore")
                return r.status, txt, str(r.url)

    async def get_json(self, url: str, headers: Optional[dict] = None, timeout: int = REQUEST_TIMEOUT):
        async with self.session_ctx() as s:
            async with s.get(url, headers=headers, proxy=self.proxy, timeout=timeout, allow_redirects=True) as r:
                return r.status, await r.json(content_type=None), str(r.url)

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

    async def post_json(self, url: str, json_payload: dict, headers: Optional[dict] = None, timeout: int = REQUEST_TIMEOUT):
        async with self.session_ctx() as s:
            async with s.post(url, json=json_payload, headers=headers, proxy=self.proxy, timeout=timeout) as r:
                txt = await r.text(errors="ignore")
                return r.status, txt, str(r.url)

    async def post_file(self, url: str, file_bytes: bytes, filename: str, headers: Optional[dict] = None, timeout: int = REQUEST_TIMEOUT):
        form = aiohttp.FormData()
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        form.add_field("image", file_bytes, filename=filename, content_type=mime)
        async with self.session_ctx() as s:
            async with s.post(url, data=form, headers=headers, proxy=self.proxy, timeout=timeout) as r:
                txt = await r.text(errors="ignore")
                return r.status, txt, str(r.url)

async def with_backoff(coro: Callable, max_tries=4, base=0.6):
    last_exc = None
    for i in range(max_tries):
        try: return await coro()
        except Exception as e:
            last_exc = e
            await asyncio.sleep(base * (2 ** i) + 0.2 * i)
    if last_exc: raise last_exc

# ---------- Secure Config Helpers ----------
from base64 import urlsafe_b64encode
def _derive_key_from_password(password: str) -> bytes:
    import hashlib as _hl
    return urlsafe_b64encode(_hl.sha256(password.encode("utf-8")).digest())

def _load_secure_blob(password: str) -> dict:
    if not SECURE_FILE.exists(): return {}
    f = Fernet(_derive_key_from_password(password))
    try: return json.loads(f.decrypt(SECURE_FILE.read_bytes()).decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError): raise ValueError("Invalid master password or corrupted vault.")

def _save_secure_blob(password: str, payload: dict):
    f = Fernet(_derive_key_from_password(password))
    SECURE_FILE.write_bytes(f.encrypt(json.dumps(payload, indent=2).encode("utf-8")))

def _deep_set(obj: dict, dotted_path: str, value):
    cur = obj; parts = dotted_path.split(".")
    for p in parts[:-1]: cur = cur.setdefault(p, {})
    cur[parts[-1]] = value

def merge_configs(plain: dict, secure: dict) -> dict:
    out = json.loads(json.dumps(plain or {}))
    def _merge(dst, src):
        for k,v in (src or {}).items():
            if isinstance(v, dict): _merge(dst.setdefault(k, {}), v)
            else: dst[k] = v
    _merge(out, secure or {})
    return out

def load_config() -> dict:
    plain = {}
    if CONFIG_FILE.exists():
        try: plain = json.load(open(CONFIG_FILE, "r", encoding="utf-8"))
        except Exception: console.print(Panel("[bad]credentials.json malformed[/bad]", border_style="bad"))
    secure = {}
    master_env = os.environ.get("BD_MASTER")
    if SECURE_FILE.exists() and master_env:
        try: secure = _load_secure_blob(master_env)
        except Exception as e: console.print(f"[warn]Vault unlock via BD_MASTER failed: {e}[/warn]")
    return merge_configs(plain, secure)

def configure_credentials():
    neon_section("Configuration")
    store = Prompt.ask("[accent]Storage type[/accent] (plain/encrypted)", choices=["plain","encrypted"], default="encrypted")
    if store == "plain":
        cfg = {}
        if CONFIG_FILE.exists():
            try: cfg = json.load(open(CONFIG_FILE,"r",encoding="utf-8"))
            except Exception: cfg = {}
        while True:
            console.print("[muted]Enter dotted key (e.g., hibp.api_key) or 'done'[/muted]")
            path = Prompt.ask("Key path").strip()
            if path.lower() in ("done","exit","quit"): break
            val = Prompt.ask("Value (plaintext)").strip()
            _deep_set(cfg, path, val); console.print(f"[good]Set {path}[/good]")
        json.dump(cfg, open(CONFIG_FILE,"w",encoding="utf-8"), indent=2)
        console.print(f"[good]Saved to {CONFIG_FILE}[/good]"); return
    # encrypted
    if SECURE_FILE.exists():
        pw = getpass("Master password: ")
        try: vault = _load_secure_blob(pw)
        except Exception as e: console.print(f"[bad]{e}[/bad]"); return
    else:
        console.print("[accent]Create vault master password[/accent]")
        while True:
            p1 = getpass("New master password: "); p2 = getpass("Confirm: ")
            if p1 and p1==p2: break
            console.print("[warn]Mismatch. Try again.[/warn]")
        pw, vault = p1, {}
    while True:
        console.print("[muted]Enter dotted key (e.g., twitter.api_key) or 'done'[/muted]")
        path = Prompt.ask("Key path").strip()
        if path.lower() in ("done","exit","quit"): break
        val = Prompt.ask("Value").strip()
        _deep_set(vault, path, val); console.print(f"[good]Set {path}[/good]")
    _save_secure_blob(pw, vault)
    console.print(f"[good]Vault saved: {SECURE_FILE}[/good]")
    console.print("[accent]Tip: export BD_MASTER to unlock in headless mode[/accent]")

# ---------- Database ----------
def init_database(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY, target_id INTEGER, module TEXT, timestamp TEXT,
        summary TEXT, raw_data TEXT, FOREIGN KEY(target_id) REFERENCES targets(id),
        UNIQUE(target_id, module)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY, type TEXT, value TEXT UNIQUE,
        source_module TEXT, first_seen TEXT, last_seen TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type)')
    try: c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(text, tokenize='porter')")
    except sqlite3.OperationalError: pass
    conn.commit()

def create_case(case_name: str, primary_target: str):
    CASES_DIR.mkdir(exist_ok=True)
    db_path = CASES_DIR / f"{case_name.replace(' ','_').lower()}.db"
    if db_path.exists(): console.print(f"[warn]Case '{case_name}' already exists[/warn]"); return None, None
    try:
        conn = sqlite3.connect(db_path); init_database(conn)
        conn.cursor().execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?,?)", (primary_target,'primary'))
        conn.commit(); console.print(f"[good]✓ Case '{case_name}' created for '{primary_target}'[/good]")
        return conn, case_name
    except sqlite3.Error as e:
        console.print(f"[bad]DB error: {e}[/bad]"); return None, None

def load_case(case_name: Optional[str] = None):
    CASES_DIR.mkdir(exist_ok=True)
    if case_name:
        db = CASES_DIR / f"{case_name.replace(' ','_').lower()}.db"
        if not db.exists(): console.print(f"[bad]Case '{case_name}' not found[/bad]"); return None, None
        try: conn = sqlite3.connect(db); console.print(f"[good]✓ Case '{case_name}' loaded[/good]"); return conn, case_name
        except sqlite3.Error as e: console.print(f"[bad]DB error: {e}[/bad]"); return None, None
    cases = sorted(CASES_DIR.glob("*.db"))
    if not cases: console.print("[warn]No cases found[/warn]"); return None, None
    table = Table(title="Cases", title_style="accent"); table.add_column("ID", style="primary"); table.add_column("Case"); table.add_column("Updated")
    for i, p in enumerate(cases, 1):
        table.add_row(str(i), p.stem, datetime.fromtimestamp(p.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'))
    console.print(table); choice = IntPrompt.ask("Select", choices=[str(i) for i in range(1,len(cases)+1)])
    try: conn = sqlite3.connect(cases[int(choice)-1]); console.print(f"[good]✓ Case '{cases[int(choice)-1].stem}' loaded[/good]"); return conn, cases[int(choice)-1].stem
    except sqlite3.Error as e: console.print(f"[bad]DB error: {e}[/bad]"); return None, None

def get_primary_target(conn: sqlite3.Connection) -> str:
    conn.row_factory = sqlite3.Row; r = conn.cursor().execute("SELECT name FROM targets WHERE type='primary' LIMIT 1").fetchone()
    return r['name'] if r else 'Unknown'

def save_result_to_db(conn: sqlite3.Connection, module: str, target_name: str, result: dict):
    c = conn.cursor()
    primary_exists = c.execute("SELECT 1 FROM targets WHERE type='primary'").fetchone() is not None
    c.execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?,?)", (target_name, 'primary' if not primary_exists else 'secondary'))
    tid = c.execute("SELECT id FROM targets WHERE name=?", (target_name,)).fetchone()[0]
    c.execute("""INSERT INTO results (target_id,module,timestamp,summary,raw_data)
                 VALUES (?,?,?,?,?)
                 ON CONFLICT(target_id,module) DO UPDATE SET
                 timestamp=excluded.timestamp, summary=excluded.summary, raw_data=excluded.raw_data""",
              (tid, module, utcnow_iso(), result.get('summary',''), json.dumps(result.get('raw',{}))))
    conn.commit()

def ingest_text_fts(conn: sqlite3.Connection, text: str):
    if not text: return
    try: conn.cursor().execute("INSERT INTO notes_fts (text) VALUES (?)", (text,)); conn.commit()
    except sqlite3.OperationalError: pass

def upsert_artifact(conn: sqlite3.Connection, a_type: str, value: str, source_module: str):
    c = conn.cursor(); now = utcnow_iso()
    row = c.execute("SELECT id FROM artifacts WHERE value=?", (value,)).fetchone()
    if row: c.execute("UPDATE artifacts SET last_seen=? WHERE id=?", (now, row[0]))
    else: c.execute("INSERT OR IGNORE INTO artifacts (type,value,source_module,first_seen,last_seen) VALUES (?,?,?,?,?)", (a_type, value, source_module, now, now))
    conn.commit()

def get_all_case_results(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    rows = conn.cursor().execute("""SELECT t.name as tname, r.module, r.summary, r.raw_data, r.timestamp
                                    FROM results r JOIN targets t ON r.target_id=t.id ORDER BY r.timestamp DESC""").fetchall()
    out={}
    for row in rows:
        key=f"{row['module']}_{row['tname']}"
        if key not in out:
            out[key]={"module":row['module'],"target":row['tname'],"summary":row['summary'],"raw":json.loads(row['raw_data']) if row['raw_data'] else None}
    return out

# ---------- Artifact Extraction ----------
ARTIFACT_PATTERNS = {
    "email":  r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "phone":  r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}",
    "domain": r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
    "ip":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url":    r"https?://[^\s\"'>]+",
    "handle": r"(?<=\s|^|[@])@[A-Za-z0-9_]{2,30}"
}
def extract_artifacts(text: str) -> List[Tuple[str, str]]:
    found=[]; blob=text or ""
    for t,pat in ARTIFACT_PATTERNS.items():
        for m in re.findall(pat, blob, flags=re.I):
            v = m.strip()
            if t in ("email","domain","handle"): v=v.lower()
            found.append((t,v))
    return list({(t,v) for t,v in found})

def ingest_from_result(conn: sqlite3.Connection, module_key: str, result: dict):
    raw = result.get("raw") or {}; text_parts=[]
    def walk(x):
        if isinstance(x, dict):
            for v in x.values(): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)
        elif isinstance(x, str): text_parts.append(x)
    walk(raw); text_all="\n".join(text_parts)[:300000]
    ingest_text_fts(conn, text_all)
    for t,v in extract_artifacts(text_all): upsert_artifact(conn, t, v, module_key)

# ---------- EXIF helper ----------
def _exif_get_gps(exif_named: dict):
    try:
        gps = exif_named.get("GPSInfo"); 
        if not gps: return None
        def conv(x): 
            if isinstance(x, tuple) and len(x)==2 and x[1]: return float(x[0])/float(x[1])
            return float(x)
        lat_vals, lat_ref = gps.get(2), gps.get(1)
        lon_vals, lon_ref = gps.get(4), gps.get(3)
        if not (lat_vals and lon_vals and len(lat_vals)>=3 and len(lon_vals)>=3): return None
        lat = conv(lat_vals[0]) + conv(lat_vals[1])/60 + conv(lat_vals[2])/3600
        lon = conv(lon_vals[0]) + conv(lon_vals[1])/60 + conv(lon_vals[2])/3600
        if str(lat_ref).upper().startswith("S"): lat = -lat
        if str(lon_ref).upper().startswith("W"): lon = -lon
        return {"lat": lat, "lon": lon}
    except Exception: return None

# ---------- IP geolocation helper ----------
async def geolocate_ip(ip: str, config: dict, http: Http):
    token = (config.get("ipinfo") or {}).get("token")
    if token:
        url = f"https://ipinfo.io/{ip}?token={token}"
        try:
            async def req():
                s,t,_ = await http.get(url, timeout=REQUEST_TIMEOUT)
                if s==200:
                    data=json.loads(t); loc=data.get("loc")
                    if loc:
                        lat,lon=[float(x) for x in loc.split(",")]
                        return {"lat":lat,"lon":lon,"label":data.get("org") or data.get("city") or "ipinfo"}
                return None
            r = await with_backoff(req)
            if r: return r
        except Exception: pass
    # fallback
    url = f"http://ip-api.com/json/{ip}"
    try:
        async def req2():
            s,t,_ = await http.get(url, timeout=REQUEST_TIMEOUT)
            if s==200:
                data=json.loads(t)
                if data.get("status")=="success":
                    return {"lat":data.get("lat"),"lon":data.get("lon"),"label":data.get("org") or data.get("city") or "ip-api"}
            return None
        return await with_backoff(req2)
    except Exception: return None

# ---------- NER ----------
def apply_ner_analysis(results: dict):
    console.print(Text("\nPerforming Named Entity Recognition...", style="muted"))
    ner={"PERSON":set(),"ORG":set(),"GPE":set(),"PRODUCT":set()}
    all_text=""
    for d in results.values():
        raw=d.get("raw"); 
        if not raw: continue
        def walk(x):
            nonlocal all_text
            if isinstance(x, dict):
                for v in x.values(): walk(v)
            elif isinstance(x, list):
                for v in x: walk(v)
            elif isinstance(x, str):
                all_text += " " + x
        walk(raw)
    if not all_text.strip():
        return {"summary":"No text found for NER.","raw":{k:[] for k in ner},"module":"NER Analysis","target":"corpus"}
    doc=nlp(all_text)
    for ent in doc.ents:
        if ent.label_ in ner and len(ent.text.strip())>2: ner[ent.label_].add(ent.text.strip())
    for k in ner: ner[k]=sorted(list(ner[k]))
    return {"summary":f"Found {len(ner['PERSON'])} people, {len(ner['ORG'])} orgs, {len(ner['GPE'])} locations.","raw":ner,"module":"NER Analysis","target":"corpus"}

# ---------- Reporting ----------
def generate_interactive_graph(results: dict, primary_target: str, filename: str):
    net = Network(height="800px", width="100%", bgcolor="#0b0b14", font_color="#cdeaff", notebook=True)
    net.add_node(primary_target, color="#ff2bd1", size=25, title=f"Primary Target: {primary_target}")
    for key,d in results.items():
        if not d.get("raw") or key=="ner_analysis": continue
        mod_name=d['module'].replace("_"," ").title(); target=d['target']; node=f"{mod_name} ({target})"
        net.add_node(node, label=node, color="#00ffc6", size=15, title=d.get('summary'))
        base=primary_target if target==primary_target else target
        if base!=node: net.add_edge(base, node, color="#7df9ff")
        if target!=primary_target and not any(n.get('id')==target for n in net.nodes):
            net.add_node(target, color="#ffd166", size=20, title=f"Associated Target: {target}")
            net.add_edge(primary_target, target, color="#7df9ff")
    net.set_options('{"physics":{"barnesHut":{"gravitationalConstant":-40000,"centralGravity":0.4,"springLength":120}}}')
    net.save_graph(filename)

def export_gexf(results: dict, primary: str, out_path: str):
    g=nx.Graph(); g.add_node(primary, kind="primary")
    for d in results.values():
        if not d.get("raw"): continue
        node=f"{d['module']}::{d['target']}"; g.add_node(node, kind="module", summary=d.get("summary",""))
        g.add_edge(primary if d['target']==primary else d['target'], node)
    nx.write_gexf(g, out_path)

def generate_html_report(results: dict, primary: str, graph_file: str, out_html: str):
    HTML_TEMPLATE = """
    <!doctype html><html><head><meta charset="utf-8"><title>BioDaemon {{ target }}</title>
    <style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#0b0b14;color:#cdeaff;margin:0;padding:20px}
    h1,h2{color:#00ffc6;border-bottom:2px solid #5a32d1}
    .container{max-width:1200px;margin:auto;background:#121225;padding:25px;border-radius:10px;box-shadow:0 0 24px rgba(0,0,0,.6)}
    .section{margin-bottom:30px;padding:20px;background:#16162d;border-left:5px solid #5a32d1;border-radius:6px}
    pre{background:#0e0e1a;padding:12px;border-radius:6px;white-space:pre-wrap;word-wrap:break-word;color:#a9c6ff}
    .graph-container{width:100%;height:650px;border:none;border-radius:6px}
    a{color:#7df9ff}
    </style></head><body>
    <div class="container"><h1>BioDaemon OSINT Report: <span style="color:#ff2bd1">{{ target }}</span></h1><p>Generated: {{ ts }}</p>
    {% if results.ner_analysis %}<div class="section"><h2>Named Entity Recognition</h2><p>{{ results.ner_analysis.summary }}</p>
    {% for label, ents in results.ner_analysis.raw.items() if ents %}<h3>{{ label }}</h3><pre>{{ ents | join(', ') }}</pre>{% endfor %}</div>{% endif %}
    <div class="section"><h2>Relationship Graph</h2><iframe src="{{ graph_file }}" class="graph-container" frameborder="0"></iframe></div>
    {% for key, d in results.items() if key != 'ner_analysis' %}<div class="section"><h2>{{ d.module | replace('_',' ') | title }} on '{{ d.target }}'</h2>
    <p><b>Summary:</b> {{ d.summary | replace('\\n','<br>') | safe }}</p><h3>Raw Data</h3><pre>{{ d.raw | tojson(indent=2) }}</pre></div>{% endfor %}
    </div></body></html>"""
    tpl=Environment(autoescape=select_autoescape(['html'])).from_string(HTML_TEMPLATE)
    open(out_html,"w",encoding="utf-8").write(tpl.render(target=primary, ts=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), results=results, graph_file=Path(graph_file).name))

def export_pdf_from_html(html_path: str, pdf_path: str):
    if WeasyHTML is None: return False, "WeasyPrint not installed"
    try: WeasyHTML(filename=html_path).write_pdf(pdf_path); return True,"ok"
    except Exception as e: return False, str(e)

def generate_geo_map_from_results(results: dict, out_html: str):
    if folium is None: return False, "folium not installed"
    markers=[]
    for d in results.values():
        geo=(d.get("raw") or {}).get("geo")
        if isinstance(geo,dict) and isinstance(geo.get("lat"),(int,float)) and isinstance(geo.get("lon"),(int,float)):
            markers.append((geo["lat"],geo["lon"], f"{d.get('module')} / {d.get('target')} — {geo.get('label') or d.get('module')}"))
    if not markers: return False, "no geo points"
    lat=sum(m[0] for m in markers)/len(markers); lon=sum(m[1] for m in markers)/len(markers)
    m=folium.Map(location=[lat,lon], zoom_start=2, tiles="CartoDB dark_matter")
    for la,lo,label in markers: folium.Marker([la,lo], popup=label).add_to(m)
    m.save(out_html); return True, "ok"

# ---------- Module System ----------
ModuleSpec = Dict[str, Any]; MODULES: Dict[str, ModuleSpec] = {}
def register_module(key: str, title: str, input_type: str):
    def deco(fn: Callable):
        MODULES[key]={"key":key,"title":title,"input_type":input_type,"run":fn}; return fn
    return deco

# -------- Core/Intel Modules --------
@register_module("username_check", "Username Availability", "username")
async def mod_username_check(target: str, config: dict, http: Http) -> dict:
    found=[]
    async def check(name, fmt):
        url=fmt.format(target)
        status=await with_backoff(lambda: http.head_or_get(url))
        if status==200: found.append({"site":name,"url":url})
    await asyncio.gather(*[check(name, fmt) for name,fmt in SITES_FOR_USERNAME_CHECK.items()])
    return {"raw":{"found_on":found},"summary":f"Username '{target}' found on {len(found)} sites: {', '.join(s['site'] for s in found)}"}

@register_module("domain_info", "Domain WHOIS/DNS", "domain")
async def mod_domain_info(target: str, config: dict, http: Http) -> dict:
    loop=asyncio.get_event_loop()
    def blocking_whois():
        try: return whois.whois(target)
        except Exception as e: return {"_error":str(e)}
    w=await loop.run_in_executor(None, blocking_whois)
    dns_records={}
    for rt in ['A','MX','TXT','NS']:
        try: dns_records[rt]=[str(r) for r in dns.resolver.resolve(target, rt)]
        except Exception: dns_records[rt]=[]
    whois_map = {k:(v.isoformat() if hasattr(v,"isoformat") else v) for k,v in (w.items() if hasattr(w,"items") else (w or {})).items() if v}
    registrar=(whois_map or {}).get("registrar","N/A")
    return {"raw":{"whois":whois_map,"dns":dns_records},"summary":f"WHOIS for '{target}' found. Registrar: {registrar}."}

@register_module("hibp_email", "HaveIBeenPwned", "email")
async def mod_hibp_email(target: str, config: dict, http: Http) -> dict:
    api=(config.get("hibp") or {}).get("api_key")
    if not api or not re.match(r"[^@]+@[^@]+\.[^@]+", target): return {"raw":None,"summary":"HIBP skipped (missing API key or invalid email)"}
    headers={"hibp-api-key":api,"user-agent":"BioDaemon"}; url=f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false"
    async def req():
        async with http.session_ctx() as s:
            async with s.get(url, headers=headers, proxy=http.proxy, timeout=REQUEST_TIMEOUT) as r:
                if r.status==404: return {"raw":None,"summary":f"[good]No breaches found for {target}.[/good]"}
                r.raise_for_status(); data=await r.json()
                return {"raw":{"breaches":data},"summary":f"[bad]Found in {len(data)} breaches.[/bad] Top 5: {', '.join(b['Name'] for b in data[:5])}"}
    try: return await with_backoff(req)
    except aiohttp.ClientResponseError as e: return {"raw":None,"summary":f"HIBP API error: {e.status}"}
    except Exception as e: return {"raw":None,"summary":f"HIBP error: {e}"}

@register_module("twitter", "Twitter", "username")
async def mod_twitter(target: str, config: dict, http: Http) -> dict:
    creds=(config.get("twitter") or {})
    if not tweepy or not creds: return {"raw":None,"summary":"Twitter skipped (missing tweepy or credentials)"}
    def blocking():
        try:
            client=tweepy.Client(bearer_token=creds.get("bearer_token"),consumer_key=creds.get("api_key"),consumer_secret=creds.get("api_secret"),
                                 access_token=creds.get("access_token"),access_token_secret=creds.get("access_secret"),wait_on_rate_limit=True)
            user=client.get_user(username=target.lstrip("@"), user_fields=["public_metrics","description","location"]).data
            if not user: return {"raw":None,"summary":f"User {target} not found."}
            pm=user.public_metrics or {}
            info={"id":int(user.id),"username":user.username,"name":user.name,"description":user.description,"location":user.location,
                  "followers_count":pm.get("followers_count"),"following_count":pm.get("following_count"),"tweet_count":pm.get("tweet_count")}
            tweets_resp=client.get_users_tweets(id=user.id, max_results=20, tweet_fields=["public_metrics","created_at"])
            tweets=[{"id":int(t.id),"text":t.text,"retweets":(t.public_metrics or {}).get("retweet_count",0),"likes":(t.public_metrics or {}).get("like_count",0),
                     "created_at":t.created_at.isoformat() if t.created_at else None} for t in (tweets_resp.data or [])]
            return {"raw":{"user_info":info,"posted_tweets":tweets},"summary":f"@{info['username']} - Followers: {info['followers_count']}. Fetched {len(tweets)} tweets."}
        except Exception as e: return {"raw":None,"summary":f"Twitter API error: {e}"}
    return await asyncio.get_event_loop().run_in_executor(None, blocking)

@register_module("reddit", "Reddit", "username")
async def mod_reddit(target: str, config: dict, http: Http) -> dict:
    creds=(config.get("reddit") or {})
    if not praw or not all(creds.get(k) for k in ("client_id","client_secret","user_agent")):
        return {"raw":None,"summary":"Reddit skipped (missing praw or credentials)"}
    def blocking():
        try:
            r=praw.Reddit(client_id=creds["client_id"], client_secret=creds["client_secret"], user_agent=creds["user_agent"])
            u=r.redditor(target); comments=[]; posts=[]
            for c in u.comments.new(limit=30):
                comments.append({"subreddit":str(c.subreddit),"score":c.score,"created_utc":datetime.fromtimestamp(c.created_utc,tz=timezone.utc).isoformat(),"body":c.body[:1000]})
            for s in u.submissions.new(limit=15):
                posts.append({"subreddit":str(s.subreddit),"score":s.score,"created_utc":datetime.fromtimestamp(s.created_utc,tz=timezone.utc).isoformat(),"title":s.title,"url":s.url})
            return {"raw":{"comments":comments,"submissions":posts},"summary":f"u/{target}: {len(posts)} posts, {len(comments)} comments fetched."}
        except Exception as e: return {"raw":None,"summary":f"Reddit API error: {e}"}
    return await asyncio.get_event_loop().run_in_executor(None, blocking)

@register_module("shodan_ip","Shodan Host Intel","ip")
async def mod_shodan_ip(target, config, http):
    api=(config.get("shodan") or {}).get("api_key")
    if not api: return {"raw":None,"summary":"Shodan skipped (missing API key)"}
    url=f"https://api.shodan.io/shodan/host/{target}?key={api}"
    async def req():
        s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
        if s==200:
            data=json.loads(t); geo=None
            if isinstance(data.get("latitude"),(int,float)) and isinstance(data.get("longitude"),(int,float)):
                geo={"lat":data["latitude"],"lon":data["longitude"],"label":data.get("org") or "Shodan"}
            return {"raw":{"host":data,"geo":geo},"summary":f"Shodan: {target} | open ports: {len(data.get('ports',[]))}"}
        return {"raw":None,"summary":f"Shodan error HTTP {s}"}
    try: return await with_backoff(req)
    except Exception as e: return {"raw":None,"summary":f"Shodan error: {e}"}

@register_module("censys_ip","Censys Host Intel","ip")
async def mod_censys_ip(target, config, http):
    creds=(config.get("censys") or {}); i=creds.get("api_id"); s=creds.get("api_secret")
    if not (i and s): return {"raw":None,"summary":"Censys skipped (missing api_id/api_secret)"}
    url=f"https://search.censys.io/api/v2/hosts/{target}"
    async def req():
        async with http.session_ctx() as sess:
            auth=aiohttp.BasicAuth(i,s)
            async with sess.get(url, auth=auth, proxy=http.proxy, timeout=REQUEST_TIMEOUT) as r:
                if r.status==200:
                    data=await r.json(); d=data.get("result") or {}; loc=d.get("location") or {}; geo=None
                    if isinstance(loc.get("latitude"),(int,float)) and isinstance(loc.get("longitude"),(int,float)):
                        geo={"lat":loc["latitude"],"lon":loc["longitude"],"label":loc.get("city") or "Censys"}
                    return {"raw":{"host":d,"geo":geo},"summary":f"Censys: {target} | services: {len(d.get('services',[]))}"}
                return {"raw":None,"summary":f"Censys error HTTP {r.status}"}
    try: return await with_backoff(req)
    except Exception as e: return {"raw":None,"summary":f"Censys error: {e}"}

@register_module("geo_ip","IP Geolocation","ip")
async def mod_geo_ip(target, config, http):
    info=await geolocate_ip(target, config, http)
    return {"raw":{"geo":info},"summary":f"GeoIP: {target} → ({info['lat']:.4f}, {info['lon']:.4f})"} if info else {"raw":None,"summary":"GeoIP: no location found"}

@register_module("exif_image","Image EXIF (GPS)","path")
async def mod_exif_image(target, config, http):
    if not Image: return {"raw":None,"summary":"Pillow not installed"}
    p=Path(target)
    if not p.exists(): return {"raw":None,"summary":f"File not found: {target}"}
    try:
        img=Image.open(str(p)); ex= getattr(img,"_getexif",lambda:None)() or {}; named={}
        for k,v in (ex or {}).items(): 
            try: named[ExifTags.TAGS.get(k,k)] = v
            except Exception: named[k]=v
        gps=_exif_get_gps(named); raw={"exif":named}
        if gps: raw["geo"]=gps; s=f"EXIF: GPS → ({gps['lat']:.6f}, {gps['lon']:.6f})"
        else: s="EXIF: no GPS found"
        return {"raw":raw,"summary":s}
    except Exception as e: return {"raw":None,"summary":f"EXIF error: {e}"}

# ---- v1.6 API-free modules ----
@register_module("search_ddg", "Web Search (DuckDuckGo)", "query")
async def mod_search_ddg(target, config, http):
    import html as htmlmod
    q=target.strip()
    if not q: return {"raw":None,"summary":"DDG: empty query"}
    url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
    s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
    if s!=200: return {"raw":None,"summary":f"DDG error HTTP {s}"}
    links=[]
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', t, flags=re.I|re.S):
        href=htmlmod.unescape(m.group(1)); title=re.sub("<.*?>","",htmlmod.unescape(m.group(2))).strip()
        if href and title: links.append({"title":title[:200],"url":href})
        if len(links)>=25: break
    return {"raw":{"engine":"duckduckgo","query":q,"results":links},"summary":f"DDG: '{q}' → {len(links)} results (top {min(len(links),25)})"}

DORK_TEMPLATES = {
    "username": ['site:pastebin.com "{}"','site:pastebin.com intext:"{}"','site:github.com "{}"','site:gitlab.com "{}"','"{}" site:medium.com','"{}" site:keybase.io','"{}" filetype:pdf','"{}" inurl:profile','"{}" "email"'],
    "domain":   ['site:{} -www.{}','site:pastebin.com "{}"','inurl:{} "index of"','"@{}" filetype:txt','"@{}" filetype:csv','"@{}" "password" -github','"@{}" "confidential"'],
    "email":    ['"{}" -site:linkedin.com','"{}" filetype:pdf','site:pastebin.com "{}"'],
    "phone":    ['"{}"','"{}" site:facebook.com','"{}" site:twitter.com','"{}" filetype:pdf']
}
@register_module("dork_search","Dork Builder + Search (DDG)","query")
async def mod_dork_search(target, config, http):
    if ":" not in target: return {"raw":None,"summary":"Dorks: use kind:value (username|domain|email|phone)"}
    kind,value = target.split(":",1); kind=kind.strip().lower(); value=value.strip()
    if kind not in DORK_TEMPLATES or not value: return {"raw":None,"summary":"Dorks: unsupported kind or empty value"}
    results=[]
    for q in [tpl.format(value) for tpl in DORK_TEMPLATES[kind]]:
        try:
            url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
            s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
            if s!=200: continue
            linkset=[]
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
                href=m.group(1)
                if href and href not in linkset: linkset.append(href)
                if len(linkset)>=10: break
            results.append({"query":q,"links":linkset})
        except Exception: pass
    return {"raw":{"kind":kind,"value":value,"queries":results},"summary":f"Dorks({kind}): {len(results)} queries; {sum(len(r['links']) for r in results)} links."}

@register_module("wayback","Wayback Snapshots","url")
async def mod_wayback(target, config, http):
    base=target.strip()
    if not base: return {"raw":None,"summary":"Wayback: empty input"}
    qurl = f"http://{base}/*" if not re.match(r"^https?://", base, re.I) else base + ("/*" if not base.endswith("/*") else "")
    api=f"https://web.archive.org/cdx/search/cdx?url={aiohttp.helpers.quote(qurl,safe='')}&output=json&limit=50&fl=timestamp,original,statuscode,mimetype,length"
    s,t,_=await http.get(api, timeout=REQUEST_TIMEOUT)
    if s!=200 or not t.strip(): return {"raw":None,"summary":f"Wayback error HTTP {s}"}
    try:
        data=json.loads(t); 
        if not data or len(data)<=1: return {"raw":{"entries":[]},"summary":"Wayback: no snapshots"}
        headers,rows=data[0],data[1:]; entries=[]
        for row in rows[:200]:
            rec=dict(zip(headers,row)); ts=rec.get("timestamp")
            rec["snapshot_url"]=f"https://web.archive.org/web/{ts}/{rec.get('original')}" if ts else None
            entries.append(rec)
        return {"raw":{"entries":entries},"summary":f"Wayback: {len(entries)} snapshots"}
    except Exception: return {"raw":None,"summary":"Wayback: parse error"}

# -------- NEW v1.7 (no-API) --------
@register_module("phone_osint","Phone OSINT (no API)","phone")
async def mod_phone_osint(target, config, http):
    out={"input":target}; parsed=None; valid=False; e164=None; region=None; typestr=None; tzs=[]
    if phonenumbers:
        try:
            parsed = phonenumbers.parse(target, None)
            valid = phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed)
            e164  = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            region= phonenumbers.region_code_for_number(parsed)
            numtype= phonenumbers.number_type(parsed)
            typestr = str(numtype).split(".")[-1]
            tzs = list(getattr(phonenumbers, "timezone", None).time_zones_for_number(parsed)) if hasattr(phonenumbers,"timezone") else []
        except Exception:
            pass
    out.update({"parsed":bool(parsed),"valid":valid,"e164":e164,"region":region,"type":typestr,"time_zones":tzs})
    ddg_links=[]
    try:
        q = f"\"{e164 or target}\""
        url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
        s,t,_ = await http.get(url, timeout=REQUEST_TIMEOUT)
        if s==200:
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
                href=m.group(1); 
                if href not in ddg_links: ddg_links.append(href)
                if len(ddg_links)>=10: break
    except Exception: pass
    return {"raw":{"phone":out,"ddg":ddg_links}, "summary": f"Phone: {e164 or target} | valid={valid} region={region} type={typestr or 'N/A'} results={len(ddg_links)}"}

@register_module("email_osint","Email OSINT (no API)","email")
async def mod_email_osint(target, config, http):
    email=target.strip().lower()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email): return {"raw":None,"summary":"Email: invalid format"}
    domain=email.split("@",1)[1]
    dns_map={"MX":[],"SPF":[],"DMARC":[]}
    # MX
    try: dns_map["MX"]=[str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain,"MX")]
    except Exception: pass
    # SPF (TXT)
    try:
        for r in dns.resolver.resolve(domain,"TXT"):
            txt=str(r.strings[0] if getattr(r,"strings",None) else r.to_text()).strip().strip('"')
            if txt.lower().startswith("v=spf1"): dns_map["SPF"].append(txt)
    except Exception: pass
    # DMARC
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}","TXT"):
            txt=str(r.strings[0] if getattr(r,"strings",None) else r.to_text()).strip().strip('"')
            if txt.lower().startswith("v=dmarc1"): dns_map["DMARC"].append(txt)
    except Exception: pass
    # Gravatar existence
    md5 = hashlib.md5(email.encode("utf-8")).hexdigest()
    grav_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
    grav_exists=False
    try:
        status = await http.head_or_get(grav_url)
        grav_exists = (status==200)
    except Exception: pass
    # dork
    ddg_links=[]
    try:
        q=f"\"{email}\""
        url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q,safe="")
        s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
        if s==200:
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
                href=m.group(1)
                if href not in ddg_links: ddg_links.append(href)
                if len(ddg_links)>=10: break
    except Exception: pass
    raw={"email":email,"domain":domain,"dns":dns_map,"gravatar":{"hash":md5,"exists":grav_exists,"url":grav_url},"ddg":ddg_links}
    summary=f"Email: {email} | MX={len(dns_map['MX'])} SPF={'Y' if dns_map['SPF'] else 'N'} DMARC={'Y' if dns_map['DMARC'] else 'N'} Gravatar={'Y' if grav_exists else 'N'} results={len(ddg_links)}"
    return {"raw":raw,"summary":summary}

@register_module("image_reverse","Image Reverse Search","path")
async def mod_image_reverse(target, config, http):
    """
    Free mode: returns reverse-search links for URL or local file (upload yourself).
    Optional API: Bing Visual Search if config['bing_visual_search']['key'] present.
    - For image URL: JSON POST with {'imageInfo': {'url': ...}}
    - For local file: multipart file upload
    """
    p=Path(target); is_url = re.match(r"^https?://", target, re.I) is not None
    phash=None
    if _imagehash and Image and not is_url and p.exists() and p.is_file():
        try:
            img=Image.open(str(p)).convert("RGB")
            phash=str(_imagehash.phash(img))
        except Exception: pass

    # Free links
    def build_links(src_url: Optional[str]):
        if src_url:
            q = aiohttp.helpers.quote(src_url, safe="")
            return {
                "google": f"https://www.google.com/searchbyimage?image_url={q}",
                "yandex": f"https://yandex.com/images/search?rpt=imageview&url={q}",
                "bing":   f"https://www.bing.com/images/search?q=imgurl:{q}&view=detailv2&iss=SBI",
                "tineye": f"https://tineye.com/search?url={q}"
            }
        return {
            "google": "https://images.google.com/",
            "yandex": "https://yandex.com/images/",
            "bing":   "https://www.bing.com/visualsearch",
            "tineye": "https://tineye.com/"
        }
    links = build_links(target if is_url else None)
    raw = {"mode":"free","phash":phash,"reverse_links":links}

    # Optional: Bing Visual Search API
    bconf = (config.get("bing_visual_search") or {})
    api_key = bconf.get("key")
    endpoint = bconf.get("endpoint") or "https://api.bing.microsoft.com/v7.0/images/visualsearch"
    if api_key:
        headers = {"Ocp-Apim-Subscription-Key": api_key}
        try:
            if is_url:
                payload = {"imageInfo": {"url": target}}
                s, txt, _ = await http.post_json(endpoint, payload, headers=headers, timeout=REQUEST_TIMEOUT)
            else:
                if not p.exists() or not p.is_file():
                    return {"raw":raw, "summary": f"Image reverse-search ready | links={'url' if is_url else 'upload'} | pHash={phash or 'N/A'} (Bing: file not found)"}
                s, txt, _ = await http.post_file(endpoint, p.read_bytes(), p.name, headers=headers, timeout=REQUEST_TIMEOUT)
            if s == 200 and txt:
                # Bing returns JSON; try parse minimal fields
                try:
                    data = json.loads(txt)
                except Exception:
                    data = {"raw": txt[:4000]}
                raw["bing_visual_search"] = data
                summary = f"Image reverse-search ready + Bing API OK | pHash={phash or 'N/A'}"
                return {"raw":raw, "summary": summary}
            else:
                raw["bing_visual_search_error"] = f"HTTP {s}"
        except Exception as e:
            raw["bing_visual_search_error"] = str(e)

    return {"raw":raw, "summary": f"Image reverse-search ready | links={'url' if is_url else 'upload'} | pHash={phash or 'N/A'}"}

@register_module("linkedin_search","LinkedIn Discovery (no API)","query")
async def mod_linkedin_search(target, config, http):
    base=target.strip()
    if not base: return {"raw":None,"summary":"LinkedIn: empty query"}
    if "site:linkedin.com" not in base:
        q = f'site:linkedin.com/in OR site:linkedin.com/company {base}'
    else:
        q = base
    url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
    s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
    if s!=200: return {"raw":None,"summary":f"LinkedIn search error HTTP {s}"}
    links=[]
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', t, flags=re.I|re.S):
        href=m.group(1)
        title=re.sub("<.*?>","",m.group(2)).strip()
        if "linkedin.com" in href:
            links.append({"title":title[:200], "url":href})
        if len(links)>=25: break
    return {"raw":{"query":q,"results":links},"summary":f"LinkedIn: {len(links)} public results"}

@register_module("github_dork", "GitHub Dorking (no API)", "query")
async def mod_github_dork(target: str, config: dict, http: Http) -> dict:
    base = target.strip()
    if not base: return {"raw": None, "summary": "GitHub dork: empty query"}
    queries = []
    if base.startswith("domain:"):
        dom = base.split(":", 1)[1].strip()
        queries = [
            f'site:github.com "{dom}"',
            f'site:github.com "{dom}" password',
            f'site:github.com "{dom}" token',
            f'site:github.com "{dom}" api_key',
            f'site:github.com "{dom}" SECRET',
            f'site:github.com "{dom}" filename:.env',
            f'site:github.com "{dom}" filename:credentials',
        ]
    elif base.startswith("org:"):
        org = base.split(":", 1)[1].strip()
        queries = [
            f'site:github.com "{org}"',
            f'site:github.com "{org}" token',
            f'site:github.com "{org}" password',
            f'site:github.com "{org}" api_key',
            f'site:github.com/{org} filename:.env',
            f'site:github.com/{org} filename:credentials',
        ]
    else:
        term = base
        queries = [
            f'site:github.com "{term}"',
            f'site:github.com "{term}" token',
            f'site:github.com "{term}" password',
            f'site:github.com "{term}" api_key',
            f'site:github.com "{term}" filename:.env',
        ]
    results = []
    for q in queries:
        try:
            url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
            status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
            if status != 200: continue
            links = []
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', text, flags=re.I):
                href = m.group(1)
                if href and href not in links: links.append(href)
                if len(links) >= 10: break
            results.append({"query": q, "links": links})
        except Exception: pass
    total = sum(len(r["links"]) for r in results)
    return {"raw": {"queries": results}, "summary": f"GitHub dorking: {len(results)} queries, {total} links"}

@register_module("pastebin_search", "Pastebin Search (no API)", "query")
async def mod_pastebin_search(target: str, config: dict, http: Http) -> dict:
    base = target.strip()
    if not base: return {"raw": None, "summary": "Pastebin: empty query"}
    # keep it simple: just a few broad variants
    queries = [
        f'site:pastebin.com "{base}"',
        f'site:pastebin.com intext:"{base}"',
        f'site:pastebin.com "{base}" email',
        f'site:pastebin.com "{base}" password',
    ]
    results = []
    for q in queries:
        try:
            url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
            status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
            if status != 200: continue
            links = []
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', text, flags=re.I):
                href = m.group(1)
                if href and href not in links: links.append(href)
                if len(links) >= 10: break
            results.append({"query": q, "links": links})
        except Exception: pass
    total = sum(len(r["links"]) for r in results)
    return {"raw": {"queries": results}, "summary": f"Pastebin: {len(results)} queries, {total} links"}

# ---------- Runner ----------
async def run_modules(conn: sqlite3.Connection, selections: List[Tuple[str,str]], config: dict, http: Http):
    tasks=[]
    for mkey,targ in selections:
        mod=MODULES.get(mkey)
        if not mod or not targ: continue
        async def _run(m=mod,t=targ):
            try:
                res=await m["run"](t, config, http)
                if res and (res.get("raw") is not None or res.get("summary")):
                    save_result_to_db(conn, m["key"], t, res); ingest_from_result(conn, m["key"], res)
                    console.print(f"[good]✓ {m['title']} finished:[/good] {res.get('summary','(no summary)')}")
                else:
                    console.print(f"[warn]• {m['title']} yielded no data.[/warn]")
            except Exception as e:
                console.print(f"[bad]✗ {m['title']} on '{t}' failed: {e}[/bad]")
        tasks.append(_run())
    if tasks: await asyncio.gather(*tasks)

# ---------- CLI / Interactive ----------
def capability_table(config: dict):
    table=Table(title="Capabilities", title_style="accent"); table.add_column("Module/Feature", style="primary"); table.add_column("Status")
    def ok(b): return "[good]enabled[/good]" if b else "[warn]limited[/warn]"
    table.add_row("Twitter", ok(tweepy and config.get("twitter")))
    table.add_row("Reddit", ok(praw and config.get("reddit") and all((config["reddit"].get(k) for k in ("client_id","client_secret","user_agent")))))
    table.add_row("HIBP", ok((config.get("hibp") or {}).get("api_key")))
    table.add_row("Shodan", ok((config.get("shodan") or {}).get("api_key")))
    table.add_row("Censys", ok((config.get("censys") or {}).get("api_id") and (config.get("censys") or {}).get("api_secret")))
    table.add_row("GeoIP             "geopy", "folium", "weasyprint", "cryptography",
            "phonenumbers", "ImageHash"
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
import whois, dns.resolver, spacy, networkx as nx
from pyvis.network import Network
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken

# Optional libs
try: import tweepy
except Exception: tweepy = None
try: import praw
except Exception: praw = None
try:
    from weasyprint import HTML as WeasyHTML
except Exception: WeasyHTML = None
try:
    from PIL import Image, ExifTags
except Exception:
    Image = None; ExifTags = None
try: import phonenumbers
except Exception: phonenumbers = None
try: import imagehash as _imagehash
except Exception: _imagehash = None
try: import folium
except Exception: folium = None

# ---------- Cyberpunk UI Theme ----------
CYBER_THEME = Theme({
    "primary": "#00FFC6",
    "accent":  "#7DF9FF",
    "warn":    "#FFD166",
    "bad":     "#FF006E",
    "good":    "#4AF626",
    "muted":   "#8A8F98",
    "panel_border": "#5A32D1"
})
console = Console(theme=CYBER_THEME)

def neon_header(title: str, subtitle: str = ""):
    big = Text(title, style="primary bold")
    content = Align.center(Text.assemble(big, "\n", Text(subtitle, style="accent")) if subtitle else big)
    console.print(Panel(content, border_style="panel_border", title="[accent]BioDaemon[/accent]", subtitle="[muted]OSINT[/muted]"))

def neon_section(title: str):
    console.print(Panel(Text(title, style="accent bold"), border_style="panel_border"))

# ---------- Globals & Config ----------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
CONFIG_FILE = Path("credentials.json")
SECURE_FILE = Path("credentials.sec")
CASES_DIR = Path("cases")
REQUEST_TIMEOUT = 25
DEFAULT_UA = "BioDaemon/1.7.1"
REPORTS_DIRNAME = "reports"

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
    try: return spacy.load("en_core_web_trf")
    except Exception:
        try: return spacy.load("en_core_web_sm")
        except OSError:
            console.print(Panel("[bad]spaCy model not found. Installing 'en_core_web_sm'...[/bad]", border_style="bad"))
            subprocess.call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
            return spacy.load("en_core_web_sm")
nlp = load_nlp()

def utcnow_iso(): return datetime.now(timezone.utc).isoformat()

# ---------- Async HTTP with Backoff ----------
class Http:
    def __init__(self, ua: str = DEFAULT_UA, max_conn: int = 50, proxy: Optional[str] = None):
        self.ua = ua
        self.conn = aiohttp.TCPConnector(limit=max_conn)
        self.session: Optional[aiohttp.ClientSession] = None
        self.proxy = proxy

    @asynccontextmanager
    async def session_ctx(self):
        if not self.session:
            self.session = aiohttp.ClientSession(connector=self.conn, headers={"User-Agent": self.ua})
        try:
            yield self.session
        finally:
            pass

    async def close(self):
        if self.session: await self.session.close(); self.session = None

    async def get(self, url: str, timeout: int = REQUEST_TIMEOUT) -> Tuple[int, str, str]:
        async with self.session_ctx() as s:
            async with s.get(url, proxy=self.proxy, timeout=timeout, allow_redirects=True) as r:
                txt = await r.text(errors="ignore")
                return r.status, txt, str(r.url)

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

async def with_backoff(coro: Callable, max_tries=4, base=0.6):
    last_exc = None
    for i in range(max_tries):
        try: return await coro()
        except Exception as e:
            last_exc = e
            await asyncio.sleep(base * (2 ** i) + 0.2 * i)
    if last_exc: raise last_exc

# ---------- Secure Config Helpers ----------
from base64 import urlsafe_b64encode
def _derive_key_from_password(password: str) -> bytes:
    import hashlib
    return urlsafe_b64encode(hashlib.sha256(password.encode("utf-8")).digest())
def _load_secure_blob(password: str) -> dict:
    if not SECURE_FILE.exists(): return {}
    f = Fernet(_derive_key_from_password(password))
    try: return json.loads(f.decrypt(SECURE_FILE.read_bytes()).decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError): raise ValueError("Invalid master password or corrupted vault.")
def _save_secure_blob(password: str, payload: dict):
    f = Fernet(_derive_key_from_password(password))
    SECURE_FILE.write_bytes(f.encrypt(json.dumps(payload, indent=2).encode("utf-8")))
def _deep_set(obj: dict, dotted_path: str, value):
    cur = obj; parts = dotted_path.split(".")
    for p in parts[:-1]: cur = cur.setdefault(p, {})
    cur[parts[-1]] = value
def merge_configs(plain: dict, secure: dict) -> dict:
    out = json.loads(json.dumps(plain or {}))
    def _merge(dst, src):
        for k,v in (src or {}).items():
            if isinstance(v, dict): _merge(dst.setdefault(k, {}), v)
            else: dst[k] = v
    _merge(out, secure or {})
    return out
def load_config() -> dict:
    plain = {}
    if CONFIG_FILE.exists():
        try: plain = json.load(open(CONFIG_FILE, "r", encoding="utf-8"))
        except Exception: console.print(Panel("[bad]credentials.json malformed[/bad]", border_style="bad"))
    secure = {}
    master_env = os.environ.get("BD_MASTER")
    if SECURE_FILE.exists() and master_env:
        try: secure = _load_secure_blob(master_env)
        except Exception as e: console.print(f"[warn]Vault unlock via BD_MASTER failed: {e}[/warn]")
    return merge_configs(plain, secure)
def configure_credentials():
    neon_section("Configuration")
    store = Prompt.ask("[accent]Storage type[/accent] (plain/encrypted)", choices=["plain","encrypted"], default="encrypted")
    if store == "plain":
        cfg = {}
        if CONFIG_FILE.exists():
            try: cfg = json.load(open(CONFIG_FILE,"r",encoding="utf-8"))
            except Exception: cfg = {}
        while True:
            console.print("[muted]Enter dotted key (e.g., hibp.api_key) or 'done'[/muted]")
            path = Prompt.ask("Key path").strip()
            if path.lower() in ("done","exit","quit"): break
            val = Prompt.ask("Value (plaintext)").strip()
            _deep_set(cfg, path, val); console.print(f"[good]Set {path}[/good]")
        json.dump(cfg, open(CONFIG_FILE,"w",encoding="utf-8"), indent=2)
        console.print(f"[good]Saved to {CONFIG_FILE}[/good]"); return
    # encrypted
    if SECURE_FILE.exists():
        pw = getpass("Master password: ")
        try: vault = _load_secure_blob(pw)
        except Exception as e: console.print(f"[bad]{e}[/bad]"); return
    else:
        console.print("[accent]Create vault master password[/accent]")
        while True:
            p1 = getpass("New master password: "); p2 = getpass("Confirm: ")
            if p1 and p1==p2: break
            console.print("[warn]Mismatch. Try again.[/warn]")
        pw, vault = p1, {}
    while True:
        console.print("[muted]Enter dotted key (e.g., twitter.api_key) or 'done'[/muted]")
        path = Prompt.ask("Key path").strip()
        if path.lower() in ("done","exit","quit"): break
        val = Prompt.ask("Value").strip()
        _deep_set(vault, path, val); console.print(f"[good]Set {path}[/good]")
    _save_secure_blob(pw, vault)
    console.print(f"[good]Vault saved: {SECURE_FILE}[/good]")
    console.print("[accent]Tip: export BD_MASTER to unlock in headless mode[/accent]")

# ---------- Database ----------
def init_database(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY, target_id INTEGER, module TEXT, timestamp TEXT,
        summary TEXT, raw_data TEXT, FOREIGN KEY(target_id) REFERENCES targets(id),
        UNIQUE(target_id, module)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY, type TEXT, value TEXT UNIQUE,
        source_module TEXT, first_seen TEXT, last_seen TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type)')
    try: c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(text, tokenize='porter')")
    except sqlite3.OperationalError: pass
    conn.commit()
def create_case(case_name: str, primary_target: str):
    CASES_DIR.mkdir(exist_ok=True)
    db_path = CASES_DIR / f"{case_name.replace(' ','_').lower()}.db"
    if db_path.exists(): console.print(f"[warn]Case '{case_name}' already exists[/warn]"); return None, None
    try:
        conn = sqlite3.connect(db_path); init_database(conn)
        conn.cursor().execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?,?)", (primary_target,'primary'))
        conn.commit(); console.print(f"[good]✓ Case '{case_name}' created for '{primary_target}'[/good]")
        return conn, case_name
    except sqlite3.Error as e:
        console.print(f"[bad]DB error: {e}[/bad]"); return None, None
def load_case(case_name: Optional[str] = None):
    CASES_DIR.mkdir(exist_ok=True)
    if case_name:
        db = CASES_DIR / f"{case_name.replace(' ','_').lower()}.db"
        if not db.exists(): console.print(f"[bad]Case '{case_name}' not found[/bad]"); return None, None
        try: conn = sqlite3.connect(db); console.print(f"[good]✓ Case '{case_name}' loaded[/good]"); return conn, case_name
        except sqlite3.Error as e: console.print(f"[bad]DB error: {e}[/bad]"); return None, None
    cases = sorted(CASES_DIR.glob("*.db"))
    if not cases: console.print("[warn]No cases found[/warn]"); return None, None
    table = Table(title="Cases", title_style="accent"); table.add_column("ID", style="primary"); table.add_column("Case"); table.add_column("Updated")
    for i, p in enumerate(cases, 1):
        table.add_row(str(i), p.stem, datetime.fromtimestamp(p.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'))
    console.print(table); choice = IntPrompt.ask("Select", choices=[str(i) for i in range(1,len(cases)+1)])
    try: conn = sqlite3.connect(cases[int(choice)-1]); console.print(f"[good]✓ Case '{cases[int(choice)-1].stem}' loaded[/good]"); return conn, cases[int(choice)-1].stem
    except sqlite3.Error as e: console.print(f"[bad]DB error: {e}[/bad]"); return None, None
def get_primary_target(conn: sqlite3.Connection) -> str:
    conn.row_factory = sqlite3.Row
    r = conn.cursor().execute("SELECT name FROM targets WHERE type='primary' LIMIT 1").fetchone()
    return r['name'] if r else 'Unknown'
def save_result_to_db(conn: sqlite3.Connection, module: str, target_name: str, result: dict):
    c = conn.cursor()
    primary_exists = c.execute("SELECT 1 FROM targets WHERE type='primary'").fetchone() is not None
    c.execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?,?)", (target_name, 'primary' if not primary_exists else 'secondary'))
    tid = c.execute("SELECT id FROM targets WHERE name=?", (target_name,)).fetchone()[0]
    c.execute("""INSERT INTO results (target_id,module,timestamp,summary,raw_data)
                 VALUES (?,?,?,?,?)
                 ON CONFLICT(target_id,module) DO UPDATE SET
                 timestamp=excluded.timestamp, summary=excluded.summary, raw_data=excluded.raw_data""",
              (tid, module, utcnow_iso(), result.get('summary',''), json.dumps(result.get('raw',{}))))
    conn.commit()

# ---------- Artifacts & NER ----------
ARTIFACT_PATTERNS = {
    "email":  r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "phone":  r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}",
    "domain": r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
    "ip":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url":    r"https?://[^\s\"'>]+",
    "handle": r"(?<=\s|^|[@])@[A-Za-z0-9_]{2,30}"
}
def ingest_text_fts(conn: sqlite3.Connection, text: str):
    if not text: return
    try: conn.cursor().execute("INSERT INTO notes_fts (text) VALUES (?)", (text,)); conn.commit()
    except sqlite3.OperationalError: pass
def upsert_artifact(conn: sqlite3.Connection, a_type: str, value: str, source_module: str):
    c = conn.cursor(); now = utcnow_iso()
    row = c.execute("SELECT id FROM artifacts WHERE value=?", (value,)).fetchone()
    if row: c.execute("UPDATE artifacts SET last_seen=? WHERE id=?", (now, row[0]))
    else: c.execute("INSERT OR IGNORE INTO artifacts (type,value,source_module,first_seen,last_seen) VALUES (?,?,?,?,?)", (a_type, value, source_module, now, now))
    conn.commit()
def extract_artifacts(text: str) -> List[Tuple[str, str]]:
    found=[]; blob=text or ""
    for t,pat in ARTIFACT_PATTERNS.items():
        for m in re.findall(pat, blob, flags=re.I):
            v = m.strip()
            if t in ("email","domain","handle"): v = v.lower()
            found.append((t,v))
    return list({(t,v) for t,v in found})
def ingest_from_result(conn: sqlite3.Connection, module_key: str, result: dict):
    raw = result.get("raw") or {}; text_parts=[]
    def walk(x):
        if isinstance(x, dict):
            for v in x.values(): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)
        elif isinstance(x, str): text_parts.append(x)
    walk(raw); text_all="\n".join(text_parts)[:300000]
    ingest_text_fts(conn, text_all)
    for t,v in extract_artifacts(text_all): upsert_artifact(conn, t, v, module_key)

def apply_ner_analysis(results: dict):
    console.print(Text("\nPerforming Named Entity Recognition...", style="muted"))
    ner={"PERSON":set(),"ORG":set(),"GPE":set(),"PRODUCT":set()}
    all_text=""
    for d in results.values():
        raw=d.get("raw"); 
        if not raw: continue
        def walk(x):
            nonlocal all_text
            if isinstance(x, dict):
                for v in x.values(): walk(v)
            elif isinstance(x, list):
                for v in x: walk(v)
            elif isinstance(x, str):
                all_text += " " + x
        walk(raw)
    if not all_text.strip():
        return {"summary":"No text found for NER.","raw":{k:[] for k in ner},"module":"NER Analysis","target":"corpus"}
    doc=nlp(all_text)
    for ent in doc.ents:
        if ent.label_ in ner and len(ent.text.strip())>2: ner[ent.label_].add(ent.text.strip())
    for k in ner: ner[k]=sorted(list(ner[k]))
    return {"summary":f"Found {len(ner['PERSON'])} people, {len(ner['ORG'])} orgs, {len(ner['GPE'])} locations.","raw":ner,"module":"NER Analysis","target":"corpus"}

# ---------- Reporting ----------
def generate_interactive_graph(results: dict, primary_target: str, filename: str):
    net = Network(height="800px", width="100%", bgcolor="#0b0b14", font_color="#cdeaff", notebook=True)
    net.add_node(primary_target, color="#ff2bd1", size=25, title=f"Primary Target: {primary_target}")
    for key,d in results.items():
        if not d.get("raw") or key=="ner_analysis": continue
        mod_name=d['module'].replace("_"," ").title(); target=d['target']; node=f"{mod_name} ({target})"
        net.add_node(node, label=node, color="#00ffc6", size=15, title=d.get('summary'))
        base=primary_target if target==primary_target else target
        if base!=node: net.add_edge(base, node, color="#7df9ff")
        if target!=primary_target and not any(n.get('id')==target for n in net.nodes):
            net.add_node(target, color="#ffd166", size=20, title=f"Associated Target: {target}")
            net.add_edge(primary_target, target, color="#7df9ff")
    net.set_options('{"physics":{"barnesHut":{"gravitationalConstant":-40000,"centralGravity":0.4,"springLength":120}}}')
    net.save_graph(filename)
def export_gexf(results: dict, primary: str, out_path: str):
    g=nx.Graph(); g.add_node(primary, kind="primary")
    for d in results.values():
        if not d.get("raw"): continue
        node=f"{d['module']}::{d['target']}"; g.add_node(node, kind="module", summary=d.get("summary",""))
        g.add_edge(primary if d['target']==primary else d['target'], node)
    nx.write_gexf(g, out_path)
def generate_html_report(results: dict, primary: str, graph_file: str, out_html: str):
    HTML_TEMPLATE = """
    <!doctype html><html><head><meta charset="utf-8"><title>BioDaemon {{ target }}</title>
    <style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#0b0b14;color:#cdeaff;margin:0;padding:20px}
    h1,h2{color:#00ffc6;border-bottom:2px solid #5a32d1}
    .container{max-width:1200px;margin:auto;background:#121225;padding:25px;border-radius:10px;box-shadow:0 0 24px rgba(0,0,0,.6)}
    .section{margin-bottom:30px;padding:20px;background:#16162d;border-left:5px solid #5a32d1;border-radius:6px}
    pre{background:#0e0e1a;padding:12px;border-radius:6px;white-space:pre-wrap;word-wrap:break-word;color:#a9c6ff}
    .graph-container{width:100%;height:650px;border:none;border-radius:6px}
    a{color:#7df9ff}
    </style></head><body>
    <div class="container"><h1>BioDaemon OSINT Report: <span style="color:#ff2bd1">{{ target }}</span></h1><p>Generated: {{ ts }}</p>
    {% if results.ner_analysis %}<div class="section"><h2>Named Entity Recognition</h2><p>{{ results.ner_analysis.summary }}</p>
    {% for label, ents in results.ner_analysis.raw.items() if ents %}<h3>{{ label }}</h3><pre>{{ ents | join(', ') }}</pre>{% endfor %}</div>{% endif %}
    <div class="section"><h2>Relationship Graph</h2><iframe src="{{ graph_file }}" class="graph-container" frameborder="0"></iframe></div>
    {% for key, d in results.items() if key != 'ner_analysis' %}<div class="section"><h2>{{ d.module | replace('_',' ') | title }} on '{{ d.target }}'</h2>
    <p><b>Summary:</b> {{ d.summary | replace('\\n','<br>') | safe }}</p><h3>Raw Data</h3><pre>{{ d.raw | tojson(indent=2) }}</pre></div>{% endfor %}
    </div></body></html>"""
    tpl=Environment(autoescape=select_autoescape(['html'])).from_string(HTML_TEMPLATE)
    open(out_html,"w",encoding="utf-8").write(tpl.render(target=primary, ts=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), results=results, graph_file=Path(graph_file).name))
def export_pdf_from_html(html_path: str, pdf_path: str):
    if WeasyHTML is None: return False, "WeasyPrint not installed"
    try: WeasyHTML(filename=html_path).write_pdf(pdf_path); return True,"ok"
    except Exception as e: return False, str(e)
def generate_geo_map_from_results(results: dict, out_html: str):
    if folium is None: return False, "folium not installed"
    markers=[]
    for d in results.values():
        geo=(d.get("raw") or {}).get("geo")
        if isinstance(geo,dict) and isinstance(geo.get("lat"),(int,float)) and isinstance(geo.get("lon"),(int,float)):
            markers.append((geo["lat"],geo["lon"], f"{d.get('module')} / {d.get('target')} — {geo.get('label') or d.get('module')}"))
    if not markers: return False, "no geo points"
    lat=sum(m[0] for m in markers)/len(markers); lon=sum(m[1] for m in markers)/len(markers)
    m=folium.Map(location=[lat,lon], zoom_start=2, tiles="CartoDB dark_matter")
    for la,lo,label in markers: folium.Marker([la,lo], popup=label).add_to(m)
    m.save(out_html); return True, "ok"

# ---------- Module System ----------
ModuleSpec = Dict[str, Any]; MODULES: Dict[str, ModuleSpec] = {}
def register_module(key: str, title: str, input_type: str):
    def deco(fn: Callable):
        MODULES[key]={"key":key,"title":title,"input_type":input_type,"run":fn}; return fn
    return deco

# -------- Core / API modules --------
@register_module("username_check", "Username Availability", "username")
async def mod_username_check(target: str, config: dict, http: Http) -> dict:
    found=[]
    async def check(name, fmt):
        url=fmt.format(target)
        status=await with_backoff(lambda: http.head_or_get(url))
        if status==200: found.append({"site":name,"url":url})
    await asyncio.gather(*[check(name, fmt) for name,fmt in SITES_FOR_USERNAME_CHECK.items()])
    return {"raw":{"found_on":found},"summary":f"Username '{target}' found on {len(found)} sites: {', '.join(s['site'] for s in found)}"}

@register_module("domain_info", "Domain WHOIS/DNS", "domain")
async def mod_domain_info(target: str, config: dict, http: Http) -> dict:
    loop=asyncio.get_event_loop()
    def blocking_whois():
        try: return whois.whois(target)
        except Exception as e: return {"_error":str(e)}
    w=await loop.run_in_executor(None, blocking_whois)
    dns_records={}
    for rt in ['A','MX','TXT','NS']:
        try: dns_records[rt]=[str(r) for r in dns.resolver.resolve(target, rt)]
        except Exception: dns_records[rt]=[]
    whois_map = {k:(v.isoformat() if hasattr(v,"isoformat") else v) for k,v in (w.items() if hasattr(w,"items") else (w or {})).items() if v}
    registrar=(whois_map or {}).get("registrar","N/A")
    return {"raw":{"whois":whois_map,"dns":dns_records},"summary":f"WHOIS for '{target}' found. Registrar: {registrar}."}

@register_module("hibp_email", "HaveIBeenPwned", "email")
async def mod_hibp_email(target: str, config: dict, http: Http) -> dict:
    api=(config.get("hibp") or {}).get("api_key")
    if not api or not re.match(r"[^@]+@[^@]+\.[^@]+", target): return {"raw":None,"summary":"HIBP skipped (missing API key or invalid email)"}
    headers={"hibp-api-key":api,"user-agent":"BioDaemon"}; url=f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false"
    async def req():
        async with http.session_ctx() as s:
            async with s.get(url, headers=headers, proxy=http.proxy, timeout=REQUEST_TIMEOUT) as r:
                if r.status==404: return {"raw":None,"summary":f"[good]No breaches found for {target}.[/good]"}
                r.raise_for_status(); data=await r.json()
                return {"raw":{"breaches":data},"summary":f"[bad]Found in {len(data)} breaches.[/bad] Top 5: {', '.join(b['Name'] for b in data[:5])}"}
    try: return await with_backoff(req)
    except aiohttp.ClientResponseError as e: return {"raw":None,"summary":f"HIBP API error: {e.status}"}
    except Exception as e: return {"raw":None,"summary":f"HIBP error: {e}"}

@register_module("twitter", "Twitter", "username")
async def mod_twitter(target: str, config: dict, http: Http) -> dict:
    creds=(config.get("twitter") or {})
    if not tweepy or not creds: return {"raw":None,"summary":"Twitter skipped (missing tweepy or credentials)"}
    def blocking():
        try:
            client=tweepy.Client(bearer_token=creds.get("bearer_token"),consumer_key=creds.get("api_key"),consumer_secret=creds.get("api_secret"),
                                 access_token=creds.get("access_token"),access_token_secret=creds.get("access_secret"),wait_on_rate_limit=True)
            user=client.get_user(username=target.lstrip("@"), user_fields=["public_metrics","description","location"]).data
            if not user: return {"raw":None,"summary":f"User {target} not found."}
            pm=user.public_metrics or {}
            info={"id":int(user.id),"username":user.username,"name":user.name,"description":user.description,"location":user.location,
                  "followers_count":pm.get("followers_count"),"following_count":pm.get("following_count"),"tweet_count":pm.get("tweet_count")}
            tweets_resp=client.get_users_tweets(id=user.id, max_results=20, tweet_fields=["public_metrics","created_at"])
            tweets=[{"id":int(t.id),"text":t.text,"retweets":(t.public_metrics or {}).get("retweet_count",0),"likes":(t.public_metrics or {}).get("like_count",0),
                     "created_at":t.created_at.isoformat() if t.created_at else None} for t in (tweets_resp.data or [])]
            return {"raw":{"user_info":info,"posted_tweets":tweets},"summary":f"@{info['username']} - Followers: {info['followers_count']}. Fetched {len(tweets)} tweets."}
        except Exception as e: return {"raw":None,"summary":f"Twitter API error: {e}"}
    return await asyncio.get_event_loop().run_in_executor(None, blocking)

@register_module("reddit", "Reddit", "username")
async def mod_reddit(target: str, config: dict, http: Http) -> dict:
    creds=(config.get("reddit") or {})
    if not praw or not all(creds.get(k) for k in ("client_id","client_secret","user_agent")):
        return {"raw":None,"summary":"Reddit skipped (missing praw or credentials)"}
    def blocking():
        try:
            r=praw.Reddit(client_id=creds["client_id"], client_secret=creds["client_secret"], user_agent=creds["user_agent"])
            u=r.redditor(target); comments=[]; posts=[]
            for c in u.comments.new(limit=30):
                comments.append({"subreddit":str(c.subreddit),"score":c.score,"created_utc":datetime.fromtimestamp(c.created_utc,tz=timezone.utc).isoformat(),"body":c.body[:1000]})
            for s in u.submissions.new(limit=15):
                posts.append({"subreddit":str(s.subreddit),"score":s.score,"created_utc":datetime.fromtimestamp(s.created_utc,tz=timezone.utc).isoformat(),"title":s.title,"url":s.url})
            return {"raw":{"comments":comments,"submissions":posts},"summary":f"u/{target}: {len(posts)} posts, {len(comments)} comments fetched."}
        except Exception as e: return {"raw":None,"summary":f"Reddit API error: {e}"}
    return await asyncio.get_event_loop().run_in_executor(None, blocking)

# -------- Shodan / Censys / GeoIP (optional API) --------
@register_module("shodan_ip","Shodan Host Intel","ip")
async def mod_shodan_ip(target, config, http):
    api=(config.get("shodan") or {}).get("api_key")
    if not api: return {"raw":None,"summary":"Shodan skipped (missing API key)"}
    url=f"https://api.shodan.io/shodan/host/{target}?key={api}"
    async def req():
        s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
        if s==200:
            data=json.loads(t); geo=None
            if isinstance(data.get("latitude"),(int,float)) and isinstance(data.get("longitude"),(int,float)):
                geo={"lat":data["latitude"],"lon":data["longitude"],"label":data.get("org") or "Shodan"}
            return {"raw":{"host":data,"geo":geo},"summary":f"Shodan: {target} | open ports: {len(data.get('ports',[]))}"}
        return {"raw":None,"summary":f"Shodan error HTTP {s}"}
    try: return await with_backoff(req)
    except Exception as e: return {"raw":None,"summary":f"Shodan error: {e}"}

@register_module("censys_ip","Censys Host Intel","ip")
async def mod_censys_ip(target, config, http):
    creds=(config.get("censys") or {}); i=creds.get("api_id"); s=creds.get("api_secret")
    if not (i and s): return {"raw":None,"summary":"Censys skipped (missing api_id/api_secret)"}
    url=f"https://search.censys.io/api/v2/hosts/{target}"
    async def req():
        async with http.session_ctx() as sess:
            auth=aiohttp.BasicAuth(i,s)
            async with sess.get(url, auth=auth, proxy=http.proxy, timeout=REQUEST_TIMEOUT) as r:
                if r.status==200:
                    data=await r.json(); d=data.get("result") or {}; loc=d.get("location") or {}; geo=None
                    if isinstance(loc.get("latitude"),(int,float)) and isinstance(loc.get("longitude"),(int,float)):
                        geo={"lat":loc["latitude"],"lon":loc["longitude"],"label":loc.get("city") or "Censys"}
                    return {"raw":{"host":d,"geo":geo},"summary":f"Censys: {target} | services: {len(d.get('services',[]))}"}
                return {"raw":None,"summary":f"Censys error HTTP {r.status}"}
    try: return await with_backoff(req)
    except Exception as e: return {"raw":None,"summary":f"Censys error: {e}"}

@register_module("geo_ip","IP Geolocation","ip")
async def mod_geo_ip(target, config, http):
    # free fallback: ip-api.com (no key)
    url = f"http://ip-api.com/json/{target}"
    s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
    if s==200:
        data=json.loads(t)
        if data.get("status")=="success":
            geo={"lat":data.get("lat"),"lon":data.get("lon"),"label":data.get("org") or data.get("city") or "ip-api"}
            return {"raw":{"geo":geo},"summary":f"GeoIP: {target} → ({geo['lat']:.4f}, {geo['lon']:.4f})"}
    return {"raw":None,"summary":"GeoIP: no location found"}

# -------- Files / EXIF --------
def _exif_get_gps(exif_named: dict):
    try:
        gps = exif_named.get("GPSInfo"); 
        if not gps: return None
        def conv(x): 
            if isinstance(x, tuple) and len(x)==2 and x[1]: return float(x[0])/float(x[1])
            return float(x)
        lat_vals, lat_ref = gps.get(2), gps.get(1)
        lon_vals, lon_ref = gps.get(4), gps.get(3)
        if not (lat_vals and lon_vals and len(lat_vals)>=3 and len(lon_vals)>=3): return None
        lat = conv(lat_vals[0]) + conv(lat_vals[1])/60 + conv(lat_vals[2])/3600
        lon = conv(lon_vals[0]) + conv(lon_vals[1])/60 + conv(lon_vals[2])/3600
        if str(lat_ref).upper().startswith("S"): lat = -lat
        if str(lon_ref).upper().startswith("W"): lon = -lon
        return {"lat": lat, "lon": lon}
    except Exception: return None

@register_module("exif_image","Image EXIF (GPS)","path")
async def mod_exif_image(target, config, http):
    if not Image: return {"raw":None,"summary":"Pillow not installed"}
    p=Path(target)
    if not p.exists(): return {"raw":None,"summary":f"File not found: {target}"}
    try:
        img=Image.open(str(p)); ex= getattr(img,"_getexif",lambda:None)() or {}; named={}
        for k,v in (ex or {}).items(): 
            try: named[ExifTags.TAGS.get(k,k)] = v
            except Exception: named[k]=v
        gps=_exif_get_gps(named); raw={"exif":named}
        if gps: raw["geo"]=gps; s=f"EXIF: GPS → ({gps['lat']:.6f}, {gps['lon']:.6f})"
        else: s="EXIF: no GPS found"
        return {"raw":raw,"summary":s}
    except Exception as e: return {"raw":None,"summary":f"EXIF error: {e}"}

# -------- Search (no API) --------
@register_module("search_ddg", "Web Search (DuckDuckGo)", "query")
async def mod_search_ddg(target, config, http):
    import html as htmlmod
    q=target.strip()
    if not q: return {"raw":None,"summary":"DDG: empty query"}
    url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
    s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
    if s!=200: return {"raw":None,"summary":f"DDG error HTTP {s}"}
    links=[]
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', t, flags=re.I|re.S):
        href=htmlmod.unescape(m.group(1)); title=re.sub("<.*?>","",htmlmod.unescape(m.group(2))).strip()
        if href and title: links.append({"title":title[:200],"url":href})
        if len(links)>=25: break
    return {"raw":{"engine":"duckduckgo","query":q,"results":links},"summary":f"DDG: '{q}' → {len(links)} results (top {min(len(links),25)})"}

DORK_TEMPLATES = {
    "username": ['site:pastebin.com "{}"','site:github.com "{}"','"{}" site:medium.com','"{}" filetype:pdf','"{}" inurl:profile'],
    "domain":   ['site:{} -www.{}','site:pastebin.com "{}"','inurl:{} "index of"','"@{}" filetype:txt','"@{}" filetype:csv','"@{}" "password" -github'],
    "email":    ['"{}" -site:linkedin.com','"{}" filetype:pdf','site:pastebin.com "{}"'],
    "phone":    ['"{}"','"{}" site:facebook.com','"{}" site:twitter.com','"{}" filetype:pdf']
}
@register_module("dork_search","Dork Builder + Search (DDG)","query")
async def mod_dork_search(target, config, http):
    if ":" not in target: return {"raw":None,"summary":"Dorks: use kind:value (username|domain|email|phone)"}
    kind,value = target.split(":",1); kind=kind.strip().lower(); value=value.strip()
    if kind not in DORK_TEMPLATES or not value: return {"raw":None,"summary":"Dorks: unsupported kind or empty value"}
    results=[]
    for q in [tpl.format(value) for tpl in DORK_TEMPLATES[kind]]:
        try:
            url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
            s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
            if s!=200: continue
            linkset=[]
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
                href=m.group(1)
                if href and href not in linkset: linkset.append(href)
                if len(linkset)>=10: break
            results.append({"query":q,"links":linkset})
        except Exception: pass
    return {"raw":{"kind":kind,"value":value,"queries":results},"summary":f"Dorks({kind}): {len(results)} queries; {sum(len(r['links']) for r in results)} links."}

@register_module("wayback","Wayback Snapshots","url")
async def mod_wayback(target, config, http):
    base=target.strip()
    if not base: return {"raw":None,"summary":"Wayback: empty input"}
    qurl = f"http://{base}/*" if not re.match(r"^https?://", base, re.I) else base + ("/*" if not base.endswith("/*") else "")
    api=f"https://web.archive.org/cdx/search/cdx?url={aiohttp.helpers.quote(qurl,safe='')}&output=json&limit=50&fl=timestamp,original,statuscode,mimetype,length"
    s,t,_=await http.get(api, timeout=REQUEST_TIMEOUT)
    if s!=200 or not t.strip(): return {"raw":None,"summary":f"Wayback error HTTP {s}"}
    try:
        data=json.loads(t); 
        if not data or len(data)<=1: return {"raw":{"entries":[]},"summary":"Wayback: no snapshots"}
        headers,rows=data[0],data[1:]; entries=[]
        for row in rows[:200]:
            rec=dict(zip(headers,row)); ts=rec.get("timestamp")
            rec["snapshot_url"]=f"https://web.archive.org/web/{ts}/{rec.get('original')}" if ts else None
            entries.append(rec)
        return {"raw":{"entries":entries},"summary":f"Wayback: {len(entries)} snapshots"}
    except Exception: return {"raw":None,"summary":"Wayback: parse error"}

# -------- No-API Recon: phone/email/image/linkedin --------
@register_module("phone_osint","Phone OSINT (no API)","phone")
async def mod_phone_osint(target, config, http):
    out={"input":target}; parsed=None; valid=False; e164=None; region=None; typestr=None; tzs=[]
    if phonenumbers:
        try:
            parsed = phonenumbers.parse(target, None)
            valid = phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed)
            e164  = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            region= phonenumbers.region_code_for_number(parsed)
            numtype= phonenumbers.number_type(parsed); typestr = str(numtype).split(".")[-1]
            tzs = list(getattr(phonenumbers, "timezone", None).time_zones_for_number(parsed)) if hasattr(phonenumbers,"timezone") else []
        except Exception:
            pass
    out.update({"parsed":bool(parsed),"valid":valid,"e164":e164,"region":region,"type":typestr,"time_zones":tzs})
    ddg_links=[]
    try:
        q = f"\"{e164 or target}\""
        url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
        s,t,_ = await http.get(url, timeout=REQUEST_TIMEOUT)
        if s==200:
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
                href=m.group(1); 
                if href not in ddg_links: ddg_links.append(href)
                if len(ddg_links)>=10: break
    except Exception: pass
    return {"raw":{"phone":out,"ddg":ddg_links}, "summary": f"Phone: {e164 or target} | valid={valid} region={region} type={typestr or 'N/A'} results={len(ddg_links)}"}

@register_module("email_osint","Email OSINT (no API)","email")
async def mod_email_osint(target, config, http):
    email=target.strip().lower()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email): return {"raw":None,"summary":"Email: invalid format"}
    domain=email.split("@",1)[1]
    dns_map={"MX":[],"SPF":[],"DMARC":[]}
    try: dns_map["MX"]=[str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain,"MX")]
    except Exception: pass
    try:
        for r in dns.resolver.resolve(domain,"TXT"):
            txt=str(r.strings[0] if getattr(r,"strings",None) else r.to_text()).strip().strip('"')
            if txt.lower().startswith("v=spf1"): dns_map["SPF"].append(txt)
    except Exception: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}","TXT"):
            txt=str(r.strings[0] if getattr(r,"strings",None) else r.to_text()).strip().strip('"')
            if txt.lower().startswith("v=dmarc1"): dns_map["DMARC"].append(txt)
    except Exception: pass
    md5 = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    grav_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
    grav_exists=False
    try:
        status = await http.head_or_get(grav_url)
        grav_exists = (status==200)
    except Exception: pass
    ddg_links=[]
    try:
        q=f"\"{email}\""
        url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q,safe="")
        s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
        if s==200:
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
                href=m.group(1)
                if href not in ddg_links: ddg_links.append(href)
                if len(ddg_links)>=10: break
    except Exception: pass
    raw={"email":email,"domain":domain,"dns":dns_map,"gravatar":{"hash":md5,"exists":grav_exists,"url":grav_url},"ddg":ddg_links}
    summary=f"Email: {email} | MX={len(dns_map['MX'])} SPF={'Y' if dns_map['SPF'] else 'N'} DMARC={'Y' if dns_map['DMARC'] else 'N'} Gravatar={'Y' if grav_exists else 'N'} results={len(ddg_links)}"
    return {"raw":raw,"summary":summary}

@register_module("image_reverse","Image Reverse Search","path")
async def mod_image_reverse(target, config, http):
    p=Path(target); is_url = bool(re.match(r"^https?://", target, re.I))
    phash=None
    if _imagehash and Image and p.exists() and p.is_file():
        try:
            img=Image.open(str(p)).convert("RGB")
            phash=str(_imagehash.phash(img))
        except Exception: pass
    links = {}
    if is_url:
        q = aiohttp.helpers.quote(target, safe="")
        links = {
            "google": f"https://www.google.com/searchbyimage?image_url={q}",
            "yandex": f"https://yandex.com/images/search?rpt=imageview&url={q}",
            "bing":   f"https://www.bing.com/images/search?q=imgurl:{q}&view=detailv2&iss=SBI",
            "tineye": f"https://tineye.com/search?url={q}"
        }
    else:
        links = {
            "google": "https://images.google.com/",
            "yandex": "https://yandex.com/images/",
            "bing":   "https://www.bing.com/visualsearch",
            "tineye": "https://tineye.com/"
        }
    # Optional API (Bing Visual Search)
    api_key = (config.get("bing") or {}).get("visual_search_key")
    api_ep  = (config.get("bing") or {}).get("visual_search_endpoint")  # e.g., https://api.bing.microsoft.com/v7.0/images/visualsearch
    api_result=None
    if api_key and api_ep and is_url:
        try:
            async with http.session_ctx() as s:
                headers={"Ocp-Apim-Subscription-Key": api_key}
                payload={"imageInfo":{"url":target}}
                r=await s.post(api_ep, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
                if r.status==200:
                    api_result=await r.json()
        except Exception:
            api_result=None
    return {"raw":{"phash":phash,"reverse_links":links,"bing_api":api_result}, "summary": f"Image reverse-search ready | {'URL' if is_url else 'upload'} mode | pHash={phash or 'N/A'}"}

@register_module("linkedin_search","LinkedIn Discovery (no API)","query")
async def mod_linkedin_search(target, config, http):
    base=target.strip()
    if not base: return {"raw":None,"summary":"LinkedIn: empty query"}
    q = base if "site:linkedin.com" in base else f'site:linkedin.com/in OR site:linkedin.com/company {base}'
    url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
    s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
    if s!=200: return {"raw":None,"summary":f"LinkedIn search error HTTP {s}"}
    links=[]
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', t, flags=re.I|re.S):
        href=m.group(1); title=re.sub("<.*?>","",m.group(2)).strip()
        if "linkedin.com" in href: links.append({"title":title[:200], "url":href})
        if len(links)>=25: break
    return {"raw":{"query":q,"results":links},"summary":f"LinkedIn: {len(links)} public results"}

# -------- No-API: GitHub Dorking / Pastebin --------
@register_module("github_dork", "GitHub Dorking (no API)", "query")
async def mod_github_dork(target: str, config: dict, http: Http) -> dict:
    base = target.strip()
    if not base: return {"raw": None, "summary": "GitHub dork: empty query"}
    queries=[]
    if base.startswith("domain:"):
        dom = base.split(":",1)[1].strip()
        queries = [f'site:github.com "{dom}"', f'site:github.com "{dom}" token', f'site:github.com "{dom}" password',
                   f'site:github.com "{dom}" api_key', f'site:github.com "{dom}" filename:.env', f'site:github.com "{dom}" filename:credentials']
    elif base.startswith("org:"):
        org = base.split(":",1)[1].strip()
        queries = [f'site:github.com/{org} filename:.env', f'site:github.com/{org} filename:credentials', f'site:github.com "{org}" token']
    else:
        term = base
        queries = [f'site:github.com "{term}"', f'site:github.com "{term}" token', f'site:github.com "{term}" api_key',
                   f'site:github.com "{term}" password', f'site:github.com "{term}" filename:.env']
    results=[]
    for q in queries:
        try:
            url = "https://html.duckduckgo.com/html/?q=" + aiohttp.helpers.quote(q, safe="")
            status, text, _ = await http.get(url, timeout=REQUEST_TIMEOUT)
            if status != 200: continue
            links=[]; 
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', text, flags=re.I):
                href=m.group(1)
                if href and href not in links: links.append(href)
                if len(links) >= 10: break
            results.append({"query": q, "links": links})
        except Exception: pass
    total = sum(len(r["links"]) for r in results)
    return {"raw": {"queries": results}, "summary": f"GitHub dorks: {len(results)} queries, {total} links."}

@register_module("pastebin_search", "Pastebin Search (no API)", "query")
async def mod_pastebin_search(target: str, config: dict, http: Http) -> dict:
    base=target.strip()
    if not base: return {"raw":None,"summary":"Pastebin: empty query"}
    q=f'site:pastebin.com "{base}"'
    url="https://html.duckduckgo.com/html/?q="+aiohttp.helpers.quote(q, safe="")
    s,t,_=await http.get(url, timeout=REQUEST_TIMEOUT)
    if s!=200: return {"raw":None,"summary":f"Pastebin search error HTTP {s}"}
    links=[]
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', t, flags=re.I):
        href=m.group(1)
        if href and href not in links: links.append(href)
        if len(links)>=25: break
    return {"raw":{"query":q,"links":links},"summary":f"Pastebin: {len(links)} results"}

# ---------- Runner ----------
async def run_modules(conn: sqlite3.Connection, selections: List[Tuple[str,str]], config: dict, http: Http):
    tasks=[]
    for mkey,targ in selections:
        mod=MODULES.get(mkey)
        if not mod or not targ: continue
        async def _run(m=mod,t=targ):
            try:
                res=await m["run"](t, config, http)
                if res and (res.get("raw") is not None or res.get("summary")):
                    save_result_to_db(conn, m["key"], t, res); ingest_from_result(conn, m["key"], res)
                    console.print(f"[good]✓ {m['title']} finished:[/good] {res.get('summary','(no summary)')}")
                else:
                    console.print(f"[warn]• {m['title']} yielded no data.[/warn]")
            except Exception as e:
                console.print(f"[bad]✗ {m['title']} on '{t}' failed: {e}[/bad]")
        tasks.append(_run())
    if tasks: await asyncio.gather(*tasks)

# ---------- UI Helpers ----------
def capability_table(config: dict):
    table=Table(title="Capabilities", title_style="accent"); table.add_column("Module/Feature", style="primary"); table.add_column("Status")
    def ok(b): return "[good]enabled[/good]" if b else "[warn]limited[/warn]"
    table.add_row("Twitter", ok(tweepy and config.get("twitter")))
    table.add_row("Reddit", ok(praw and config.get("reddit") and all((config["reddit"].get(k) for k in ("client_id","client_secret","user_agent")))))
    table.add_row("HIBP", ok((config.get("hibp") or {}).get("api_key")))
    table.add_row("Shodan", ok((config.get("shodan") or {}).get("api_key")))
    table.add_row("Censys", ok((config.get("censys") or {}).get("api_id") and (config.get("censys") or {}).get("api_secret")))
    table.add_row("Bing Visual Search", ok((config.get("bing") or {}).get("visual_search_key")))
    table.add_row("Folium (GeoMap)", ok(folium is not None))
    table.add_row("DDG Search / Dorks / Wayback", ok(True))
    table.add_row("Phone/Email/Image/LinkedIn (no API)", ok(True))
    table.add_row("GitHub Dork / Pastebin (no API)", ok(True))
    console.print(table)

def show_artifacts(conn: sqlite3.Connection):
    conn.row_factory=sqlite3.Row
    rows=conn.cursor().execute("SELECT type,value,source_module,first_seen,last_seen FROM artifacts ORDER BY type,value").fetchall()
    if not rows: console.print("[warn]No artifacts stored yet.[/warn]"); return
    table=Table(title="Artifacts", title_style="accent")
    table.add_column("Type",style="primary"); table.add_column("Value"); table.add_column("Source"); table.add_column("First Seen"); table.add_column("Last Seen")
    for r in rows: table.add_row(r["type"], r["value"], r["source_module"], r["first_seen"], r["last_seen"])
    console.print(table)

def make_reports(conn: sqlite3.Connection, case_name: str, report_kinds: Optional[List[str]] = None):
    console.print(Text("Gathering all case data for reporting...", style="muted"))
    # collect results
    conn.row_factory = sqlite3.Row
    rows = conn.cursor().execute("""SELECT t.name as tname, r.module, r.summary, r.raw_data, r.timestamp
                                    FROM results r JOIN targets t ON r.target_id=t.id ORDER BY r.timestamp DESC""").fetchall()
    res={}
    for row in rows:
        key=f"{row['module']}_{row['tname']}"
        if key not in res:
            res[key]={"module":row['module'],"target":row['tname'],"summary":row['summary'],"raw":json.loads(row['raw_data']) if row['raw_data'] else None}
    ner=apply_ner_analysis(res); res2=dict(res); res2["ner_analysis"]=ner; primary=get_primary_target(conn)
    ts=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    out_dir = CASES_DIR / case_name / REPORTS_DIRNAME; out_dir.mkdir(parents=True, exist_ok=True)
    graph_path=out_dir / f"graph_{case_name}_{ts}.html"
    html_path =out_dir / f"REPORT_{case_name.upper()}_{ts}.html"
    gexf_path =out_dir / f"graph_{case_name}_{ts}.gexf"
    pdf_path  =out_dir / f"REPORT_{case_name.upper()}_{ts}.pdf"
    geo_map_path=out_dir / f"geomap_{case_name}_{ts}.html"
    generate_interactive_graph(res2, primary, str(graph_path))
    generate_html_report(res2, primary, str(graph_path), str(html_path))
    export_gexf(res2, primary, str(gexf_path))
    ok_map, why_map = generate_geo_map_from_results(res2, str(geo_map_path))
    msg=f"[good]✓ Reports saved:[/good]\n- HTML: {html_path}\n- Graph: {graph_path}\n- GEXF: {gexf_path}"
    msg+=f"\n- GeoMap: {geo_map_path}" if ok_map else f"\n- GeoMap: [warn]skipped ({why_map})[/warn]"
    if report_kinds and "pdf" in report_kinds:
        ok, why=export_pdf_from_html(str(html_path), str(pdf_path))
        msg+=f"\n- PDF: {pdf_path}" if ok else f"\n- PDF: [warn]skipped ({why})[/warn]"
    console.print(msg)

def interactive_menu(conn: sqlite3.Connection, case_name: str, config: dict):
    primary=get_primary_target(conn); capability_table(config)
    while True:
        neon_section(f"Case: {case_name}  |  Primary: {primary}")
        console.print("[primary]1.[/primary] Run Modules")
        console.print("[primary]2.[/primary] Generate Report")
        console.print("[primary]3.[/primary] Show Artifacts")
        console.print("[primary]4.[/primary] Configure Credentials")
        console.print("[primary]5.[/primary] Return to Main Menu")
        action=Prompt.ask("Select", choices=["1","2","3","4","5"], default="1")
        if action=="1":
            keys=list(MODULES.keys())
            table=Table(title="Available Modules", title_style="accent")
            table.add_column("ID",style="primary"); table.add_column("Module"); table.add_column("Input")
            for i,k in enumerate(keys,1): table.add_row(str(i), MODULES[k]["title"], MODULES[k]["input_type"])
            console.print(table)
            raw_choice=Prompt.ask("Enter module IDs to run (e.g., 1,3,5)")
            try: ids=sorted({int(x.strip()) for x in raw_choice.split(",") if x.strip()})
            except Exception: console.print("[bad]Invalid selection.[/bad]"); continue
            sels=[]
            for i in ids:
                if 1<=i<=len(keys):
                    k=keys[i-1]; t=Prompt.ask(f"Target for {MODULES[k]['title']} ({MODULES[k]['input_type']})").strip()
                    sels.append((k,t))
            if not sels: console.print("[warn]No modules selected.[/warn]"); continue
            http=Http()
            try: asyncio.run(run_modules(conn, sels, config, http))
            finally: asyncio.run(http.close())
        elif action=="2": make_reports(conn, case_name)
        elif action=="3": show_artifacts(conn)
        elif action=="4": configure_credentials(); config.update(load_config())
        else: break

# ---------- Headless ----------
def parse_args():
    ap=argparse.ArgumentParser(description="BioDaemon v1.7.1 OSINT")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--new-case", type=str)
    ap.add_argument("--load-case", type=str)
    ap.add_argument("--primary", type=str)
    ap.add_argument("--modules", type=str, help="Comma-separated module keys")
    # Inputs
    ap.add_argument("--username", type=str)
    ap.add_argument("--domain", type=str)
    ap.add_argument("--email", type=str)
    ap.add_argument("--ip", type=str)
    ap.add_argument("--path", type=str, help="File path for exif_image / image_reverse")
    ap.add_argument("--query", type=str, help="Query for search_ddg / dork_search / linkedin_search / github_dork / pastebin_search")
    ap.add_argument("--url", type=str, help="URL or domain for wayback")
    ap.add_argument("--phone", type=str, help="Phone for phone_osint")
    # Network
    ap.add_argument("--proxy", type=str)
    # Report
    ap.add_argument("--report", type=str, help="html,pdf,graph,gexf")
    return ap.parse_args()

def build_selections_from_args(mod_list: List[str], args) -> List[Tuple[str,str]]:
    sels=[]
    for m in mod_list:
        spec=MODULES.get(m)
        if not spec: console.print(f"[warn]Unknown module '{m}' (skipping).[/warn]"); continue
        it=spec["input_type"]; val=None
        if it=="username": val=args.username
        elif it=="domain": val=args.domain
        elif it=="email": val=args.email
        elif it=="ip": val=args.ip
        elif it=="path": val=args.path
        elif it=="query": val=args.query
        elif it=="url": val=args.url
        elif it=="phone": val=args.phone
        if not val: console.print(f"[warn]Module '{m}' requires '{it}' input — skipping.[/warn]"); continue
        sels.append((m,val))
    return sels

def headless_flow(args, config):
    config.update(load_config())
    # case
    conn, case_name = (create_case(args.new_case, args.primary or args.username or args.domain or args.email or args.ip or args.path or args.query or args.url or args.phone or "primary") if args.new_case else load_case(args.load_case))
    if not conn: sys.exit(1)
    # modules
    mod_list=[m.strip() for m in (args.modules or "").split(",") if m.strip()]
    sels=build_selections_from_args(mod_list, args)
    if sels:
        http=Http(proxy=args.proxy)
        try: asyncio.run(run_modules(conn, sels, config, http))
        finally: asyncio.run(http.close())
    else:
        console.print("[warn]No runnable modules provided.[/warn]")
    kinds=[x.strip() for x in (args.report or "html,graph,gexf").split(",") if x.strip()]
    make_reports(conn, case_name, kinds)

# ---------- Main ----------
def main():
    neon_header("BioDaemon","OSINT Analysis Platform v1.7.1 — Neon Mode")
    config=load_config()
    args=parse_args()
    if args.headless: headless_flow(args, config); return
    conn, case_name=None,""
    while True:
        if conn: conn.close()
        neon_section("Case Management")
        console.print("[primary]1.[/primary] Create New Case")
        console.print("[primary]2.[/primary] Load Existing Case")
        console.print("[primary]3.[/primary] Configure Credentials")
        console.print("[primary]0.[/primary] Exit")
        choice=Prompt.ask("Select", choices=["1","2","3","0"], default="1")
        if choice=="1":
            name=Prompt.ask("Case name").strip()
            if name:
                primary=Prompt.ask(f"Primary target for '{name}'").strip()
                if primary: conn, case_name = create_case(name, primary)
        elif choice=="2": conn, case_name = load_case()
        elif choice=="3": configure_credentials(); config.update(load_config()); continue
        else: sys.exit(0)
        if conn:
            try: interactive_menu(conn, case_name, config)
            finally: 
                if conn: conn.close()

if __name__=="__main__":
    main()