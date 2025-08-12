# file: biodaemon_v1.1.py
"""
BioDaemon v1.1
A stable, fully integrated OSINT analysis platform with a persistent database,
case management, advanced NER analysis, and enhanced interactive reporting.
This version includes numerous bug fixes and logic improvements.
"""

import sys
import subprocess
import json
import time
import logging
import sqlite3
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# --- Dependency Management ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt, IntPrompt
    from rich.text import Text
    from rich.panel import Panel
    import requests
    import instaloader
    import tweepy
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    import praw
    import networkx as nx
    from pyvis.network import Network
    import folium
    from jinja2 import Environment
    import whois
    import dns.resolver
    import spacy
    from geopy.geocoders import Nominatim
    from PIL import Image, ExifTags
    from googlesearch import search as Google Search
except ImportError:
    console = Console()
    console.print(Panel("[yellow]Major dependencies missing. Attempting automatic installation...[/yellow]", title="Setup", border_style="yellow"))
    packages = [
        "rich", "requests[socks]", "instaloader", "tweepy", "vaderSentiment", "praw",
        "networkx", "pyvis", "folium", "jinja2", "python-whois",
        "dnspython", "spacy", "geopy", "Pillow", "googlesearch-python"
    ]
    subprocess.call([sys.executable, "-m", "pip", "install", *packages])
    console.print("\n[bold green]Core dependencies installed.[/bold green]")
    console.print("[yellow]Now downloading required NLP model for spaCy...[/yellow]")
    subprocess.call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
    console.print("\n[bold green]Setup complete. Please re-run the script.[/bold green]")
    sys.exit(0)

# --- Check for spaCy Model ---
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    console = Console()
    console.print(Panel("[bold red]SpaCy NLP model 'en_core_web_sm' not found.[/bold red]", border_style="red"))
    console.print("Please run this command in your terminal to download it:")
    console.print("[cyan]python -m spacy download en_core_web_sm[/cyan]")
    sys.exit(1)

# --- Globals & Configuration ---
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
console = Console()
CONFIG_FILE = Path("credentials.json")
CASES_DIR = Path("cases")
REQUEST_TIMEOUT = 20
SITES_FOR_USERNAME_CHECK = {"GitHub": "https://github.com/{}", "Twitter": "https://twitter.com/{}", "Instagram": "https://www.instagram.com/{}", "Reddit": "https://www.reddit.com/user/{}","Pinterest": "https://www.pinterest.com/{}", "Twitch": "https://www.twitch.tv/{}", "TikTok": "https://www.tiktok.com/@{}"}

# --- Utility Functions ---
def load_config():
    if not CONFIG_FILE.exists():
        console.print(Panel("⚠️ [yellow]credentials.json not found![/yellow]", border_style="yellow")); return {}
    try: return json.load(open(CONFIG_FILE, "r", encoding="utf-8"))
    except json.JSONDecodeError: console.print(Panel("🚨 [red]credentials.json is malformed.[/red]")); return {}

def get_session(use_tor: bool = False):
    session = requests.Session()
    if use_tor:
        session.proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
        try:
            with console.status("[cyan]Checking Tor connection...[/cyan]", spinner="earth"):
                r = session.get("https://check.torproject.org", timeout=REQUEST_TIMEOUT)
                if "Congratulations. This browser is configured to use Tor." in r.text:
                    logging.info("Tor connection successful.")
                    return session
            console.print(Panel("[red]Tor check failed.[/red]", border_style="red"))
            return None
        except requests.RequestException as e:
            logging.error(f"Tor check failed: {e}")
            console.print(Panel("[red]Tor connection failed. Is service running on port 9050?[/red]", border_style="red"))
            return None
    return session

# --- Database Management ---
def init_database(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, target_id INTEGER, module TEXT, timestamp TEXT, summary TEXT, raw_data TEXT, FOREIGN KEY(target_id) REFERENCES targets(id), UNIQUE(target_id, module))')
    conn.commit()

def create_case(case_name: str, primary_target: str):
    CASES_DIR.mkdir(exist_ok=True)
    db_path = CASES_DIR / f"{case_name.replace(' ', '_').lower()}.db"
    if db_path.exists():
        console.print(f"[yellow]Case '{case_name}' already exists.[/yellow]"); return None, None
    try:
        conn = sqlite3.connect(db_path)
        init_database(conn)
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?, ?)", (primary_target, 'primary'))
        conn.commit()
        console.print(f"[green]✓ Case '{case_name}' created for target '{primary_target}'.[/green]")
        return conn, case_name
    except sqlite3.Error as e: console.print(f"[red]DB error: {e}[/red]"); return None, None

def load_case():
    CASES_DIR.mkdir(exist_ok=True)
    cases = sorted([f for f in CASES_DIR.glob("*.db")])
    if not cases: console.print("[yellow]No existing cases found.[/yellow]"); return None, None
    table = Table(title="Existing Cases")
    table.add_column("ID", style="cyan"); table.add_column("Case Name"); table.add_column("Last Modified")
    for idx, case_path in enumerate(cases, 1):
        table.add_row(str(idx), case_path.stem, datetime.fromtimestamp(case_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'))
    console.print(table)
    choice = IntPrompt.ask("Select a case ID", choices=[str(i) for i in range(1, len(cases) + 1)])
    try:
        conn = sqlite3.connect(cases[choice - 1])
        console.print(f"[green]✓ Case '{cases[choice - 1].stem}' loaded.[/green]")
        return conn, cases[choice - 1].stem
    except sqlite3.Error as e: console.print(f"[red]DB error: {e}[/red]"); return None, None

def save_result_to_db(conn: sqlite3.Connection, module: str, target_name: str, result: dict):
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO targets (name, type) VALUES (?, ?)", (target_name, 'secondary' if not cursor.execute("SELECT id FROM targets WHERE type='primary'").fetchone() else 'primary' if cursor.execute("SELECT id FROM targets WHERE name=?", (target_name,)).fetchone() else 'secondary'))
    target_id = cursor.execute("SELECT id FROM targets WHERE name = ?", (target_name,)).fetchone()[0]
    
    # Use INSERT ON CONFLICT to simplify insert/update logic
    cursor.execute("""
        INSERT INTO results (target_id, module, timestamp, summary, raw_data)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(target_id, module) DO UPDATE SET
            timestamp=excluded.timestamp,
            summary=excluded.summary,
            raw_data=excluded.raw_data;
    """, (target_id, module, datetime.now().isoformat(), result.get('summary', ''), json.dumps(result.get('raw'))))
    conn.commit()
    logging.info(f"Saved/Updated result for '{module}' on '{target_name}' to the database.")

def get_all_case_results(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    primary_target = (cursor.execute("SELECT name FROM targets WHERE type = 'primary' LIMIT 1").fetchone() or {}).get('name', 'Unknown')
    rows = cursor.execute("SELECT t.name, r.module, r.summary, r.raw_data FROM results r JOIN targets t ON r.target_id = t.id ORDER BY r.timestamp DESC").fetchall()
    results = {}
    for row in rows:
        key = f"{row['module']}_{row['name']}"
        if key not in results:
            results[key] = {"module": row['module'], "target": row['name'], "summary": row['summary'], "raw": json.loads(row['raw_data']) if row['raw_data'] else None}
    return results, primary_target

# --- OSINT Fetcher Modules ---

def fetch_username_availability(target: str, config: dict, session: requests.Session):
    found_sites = []
    def check_site(site, url_format):
        try:
            res = session.head(url_format.format(target), timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if res.status_code == 200: found_sites.append({"site": site, "url": res.url})
        except requests.RequestException: pass
    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(check_site, SITES_FOR_USERNAME_CHECK.keys(), SITES_FOR_USERNAME_CHECK.values()))
    summary = f"Username '{target}' found on {len(found_sites)} sites: {', '.join(s['site'] for s in found_sites)}"
    return {"raw": {"found_on": found_sites}, "summary": summary}

def fetch_domain_info(target: str, config: dict, session: requests.Session):
    try:
        w = whois.whois(target)
        dns_records = {}
        for rt in ['A', 'MX', 'TXT', 'NS']:
            try: dns_records[rt] = [str(r) for r in dns.resolver.resolve(target, rt)]
            except Exception: dns_records[rt] = []
        raw = {"whois": {k: (v.isoformat() if isinstance(v, datetime) else v) for k,v in w.items() if v}, "dns": dns_records}
        summary = f"WHOIS for '{target}' found. Registrar: {w.get('registrar', 'N/A')}."
        return {"raw": raw, "summary": summary}
    except Exception as e: return {"raw": None, "summary": f"Domain info error: {e}"}

def fetch_hibp_email(target: str, config: dict, session: requests.Session):
    api_key = config.get("hibp", {}).get("api_key")
    if not api_key: return {"raw": None, "summary": "HIBP skipped (no api_key in credentials.json)"}
    if not re.match(r"[^@]+@[^@]+\.[^@]+", target): return {"raw": None, "summary": "Invalid email format."}
    headers = {"hibp-api-key": api_key, "user-agent": "BioDaemon"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
    try:
        response = session.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=REQUEST_TIMEOUT)
        if response.status_code == 404: return {"raw": None, "summary": f"[green]No breaches found for {target}.[/green]"}
        response.raise_for_status()
        breaches = response.json()
        summary = f"[bold red]Found in {len(breaches)} breaches.[/bold red] Top 5: {', '.join(b['Name'] for b in breaches[:5])}"
        return {"raw": {"breaches": breaches}, "summary": summary}
    except requests.exceptions.HTTPError as e: return {"raw": None, "summary": f"HIBP API error: {e.response.status_code}"}
    except Exception as e: return {"raw": None, "summary": f"HIBP error: {e}"}

def fetch_twitter(target: str, config: dict, session: requests.Session):
    creds = config.get("twitter")
    if not creds: return {"raw": None, "summary": "Twitter skipped (missing credentials)"}
    try:
        client = tweepy.Client(bearer_token=creds.get("bearer_token"), consumer_key=creds.get("api_key"), consumer_secret=creds.get("api_secret"), access_token=creds.get("access_token"), access_token_secret=creds.get("access_secret"), wait_on_rate_limit=True)
        user_resp = client.get_user(username=target.lstrip("@"), user_fields=["public_metrics", "description", "location"])
        user_obj = user_resp.data
        if not user_obj: return {"raw": None, "summary": f"User {target} not found."}
        pm = user_obj.public_metrics or {}
        user_info = {"id": int(user_obj.id), "username": user_obj.username, "name": user_obj.name, "description": user_obj.description, "location": user_obj.location, "followers_count": pm.get("followers_count"), "following_count": pm.get("following_count"), "tweet_count": pm.get("tweet_count")}
        tweets_resp = client.get_users_tweets(id=user_obj.id, max_results=20, tweet_fields=["public_metrics", "created_at"])
        tweets = [{"id": int(t.id), "text": t.text, "retweets": (t.public_metrics or {}).get("retweet_count",0), "likes": (t.public_metrics or {}).get("like_count",0), "created_at": t.created_at.isoformat() if t.created_at else None} for t in (tweets_resp.data or [])]
        summary = f"@{user_info['username']} - Followers: {user_info['followers_count']}. Fetched {len(tweets)} tweets."
        return {"raw": {"user_info": user_info, "posted_tweets": tweets}, "summary": summary}
    except Exception as e: return {"raw": None, "summary": f"Twitter API error: {e}"}

# --- Analysis & Reporting ---

def apply_ner_analysis(results: dict):
    console.print("\n[cyan]Performing Named Entity Recognition...[/cyan]")
    ner_results = {"PERSON": set(), "ORG": set(), "GPE": set(), "PRODUCT": set()} # GPE = Geopolitical Entity
    all_text = ""
    for data in results.values():
        raw = data.get("raw")
        if not raw: continue
        if data.get("module") == "twitter": all_text += raw.get("user_info",{}).get("description","") + " ".join([t.get("text", "") for t in raw.get("posted_tweets", [])])
        elif data.get("module") == "reddit": all_text += " ".join([c.get("body", "") for c in raw.get("comments", [])])
    doc = nlp(all_text)
    for ent in doc.ents:
        if ent.label_ in ner_results and len(ent.text.strip()) > 2: ner_results[ent.label_].add(ent.text.strip())
    for key in ner_results: ner_results[key] = sorted(list(ner_results[key]))
    results["ner_analysis"] = {"summary": f"Found {len(ner_results['PERSON'])} people, {len(ner_results['ORG'])} orgs, {len(ner_results['GPE'])} locations.", "raw": ner_results, "module": "NER Analysis", "target": "corpus"}
    return results

def generate_interactive_graph(results: dict, primary_target: str, filename: str):
    net = Network(height="800px", width="100%", bgcolor="#222222", font_color="white", notebook=True)
    net.add_node(primary_target, color="#ff4757", size=25, title=f"Primary Target: {primary_target}")
    # Add nodes for each finding
    for key, data in results.items():
        if not data.get("raw") or key == "ner_analysis": continue
        module_name = data['module'].replace("_", " ").title()
        target_name = data['target']
        node_id = f"{module_name} ({target_name})"
        net.add_node(node_id, label=node_id, color="#1e90ff", size=15, title=data.get('summary'))
        net.add_edge(primary_target if target_name == primary_target else target_name, node_id)
        if target_name != primary_target and not any(n['id'] == target_name for n in net.nodes):
            net.add_node(target_name, color="#ffa502", size=20, title=f"Associated Target: {target_name}")
            net.add_edge(primary_target, target_name)
    # Add NER entities
    if "ner_analysis" in results:
        for label, entities in results["ner_analysis"]["raw"].items():
            for entity in entities[:5]: # Limit to top 5 entities per category
                net.add_node(entity, label=entity, color="#2ed573", size=10, title=f"Found Entity ({label})")
                net.add_edge(primary_target, entity)
    net.set_options('{"physics": {"barnesHut": {"gravitationalConstant": -40000, "centralGravity": 0.4, "springLength": 120}}}')
    net.save_graph(filename)

def generate_html_report(results: dict, primary_target: str, filenames: dict):
    HTML_TEMPLATE = """
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>BioDaemon Report: {{ target }}</title>
    <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background-color:#121212;color:#e0e0e0;margin:0;padding:20px}h1,h2{color:#74b9ff;border-bottom:2px solid #74b9ff}
    .container{max-width:1200px;margin:auto;background-color:#1e1e1e;padding:25px;border-radius:8px;box-shadow:0 0 20px rgba(0,0,0,0.7)}
    .section{margin-bottom:30px;padding:20px;background-color:#2d2d2d;border-left:5px solid #74b9ff;border-radius:5px}
    pre{background-color:#191919;padding:10px;border-radius:4px;white-space:pre-wrap;word-wrap:break-word;color:#a9b7c6}
    .graph-container{width:100%;height:650px;border:none;border-radius:5px}</style></head>
    <body><div class="container"><h1>BioDaemon OSINT Report: <span style="color:#ffeaa7">{{ target }}</span></h1><p>Report generated on: {{ timestamp }}</p>
    {% if results.ner_analysis %}<div class="section"><h2>Named Entity Recognition</h2><p>{{ results.ner_analysis.summary }}</p>
    {% for label, entities in results.ner_analysis.raw.items() if entities %}<h3>{{ label }}</h3><pre>{{ entities | join(', ') }}</pre>{% endfor %}</div>{% endif %}
    <div class="section"><h2>Relationship Graph</h2><iframe src="{{ graph_file }}" class="graph-container" frameborder="0"></iframe></div>
    {% for key, data in results.items() if key != 'ner_analysis' %}<div class="section"><h2>{{ data.module | replace('_', ' ') | title }} on '{{ data.target }}'</h2>
    <p><b>Summary:</b> {{ data.summary | replace('\\n', '<br>') | safe }}</p><h3>Raw Data:</h3><pre>{{ data.raw | tojson(indent=4) }}</pre></div>{% endfor %}
    </div></body></html>
    """
    env = Environment(autoescape=select_autoescape(['html'])); template = env.from_string(HTML_TEMPLATE)
    rendered_html = template.render(target=primary_target, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'), results=results, graph_file=Path(filenames["graph"]).name)
    with open(filenames["html"], "w", encoding="utf-8") as f: f.write(rendered_html)

# --- Main Application Logic ---

def run_investigation(conn: sqlite3.Connection):
    options = {"username_check": ("Username Availability", "username"), "domain_info": ("Domain WHOIS/DNS", "domain"), "twitter": ("Twitter", "username"), "reddit": ("Reddit", "username"), "hibp_email": ("HaveIBeenPwned", "email")}
    options_list = list(options.keys())
    table = Table(title="Available Modules"); table.add_column("ID", style="cyan"); table.add_column("Module"); table.add_column("Input Type")
    for idx, name in enumerate(options_list, 1): table.add_row(str(idx), options[name][0], options[name][1])
    console.print(table)
    choice_str = Prompt.ask("Enter module IDs to run (e.g., 1,3,5)")
    selected_ids = [int(i.strip()) for i in choice_str.split(',') if i.strip().isdigit()]
    selected_modules = [options_list[i-1] for i in selected_ids if 1 <= i <= len(options_list)]
    if not selected_modules: console.print("[red]No valid modules selected.[/red]"); return
    targets = {}
    for module in selected_modules:
        prompt_text = f"Enter target for {options[module][0]} ({options[module][1]})"
        targets[module] = Prompt.ask(f"[bold]{prompt_text}[/bold]")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_map = {progress.add_task(f"[green]Running {options[plat][0]}...[/green]"): (plat, targ) for plat, targ in targets.items() if targ}
        with ThreadPoolExecutor(max_workers=len(task_map)) as executor:
            config = load_config(); session = get_session()
            future_map = {executor.submit(globals().get(f"fetch_{plat}"), targ, config, session): task_id for task_id, (plat, targ) in task_map.items()}
            for future in as_completed(future_map):
                task_id = future_map[future]; plat, targ = task_map[task_id]
                try:
                    result = future.result()
                    if result and result.get("raw"): save_result_to_db(conn, plat, targ, result)
                    console.print(f"[green]✓ {options[plat][0]} finished:[/green] {result.get('summary', 'No summary.')}")
                except Exception as e: console.print(f"[red]✗ {options[plat][0]} on '{targ}' failed: {e}[/red]")
                progress.update(task_id, completed=1)

def main():
    console.print(Panel(Text("BioDaemon", justify="center"), title="[bold #569cd6]BioDaemon[/bold #569cd6]", subtitle="[cyan]OSINT Analysis Platform v1.1[/cyan]"))
    conn, case_name = None, ""
    while True:
        if conn: conn.close()
        console.print("\n[bold]Case Management[/bold]"); console.print("[cyan]1.[/cyan] Create New Case\n[cyan]2.[/cyan] Load Existing Case\n[cyan]0.[/cyan] Exit")
        choice = Prompt.ask("Select an option", choices=["1", "2", "0"], default="1")
        if choice == "1":
            case_name_input = Prompt.ask("[bold]Enter case name[/bold]").strip()
            if case_name_input:
                primary_target_input = Prompt.ask(f"[bold]Enter primary target for '{case_name_input}'[/bold]").strip()
                if primary_target_input: conn, case_name = create_case(case_name_input, primary_target_input)
        elif choice == "2": conn, case_name = load_case()
        else: sys.exit(0)
        
        if conn:
            try:
                while True:
                    console.print(f"\n[bold]Investigation Menu for Case:[/bold] [yellow]{case_name}[/yellow]")
                    console.print("[cyan]1.[/cyan] Run Investigation Modules\n[cyan]2.[/cyan] Generate Full Case Report\n[cyan]3.[/cyan] Return to Main Menu")
                    action = Prompt.ask("Select an action", choices=["1", "2", "3"], default="1")
                    if action == "1": run_investigation(conn)
                    elif action == "2":
                        console.print("[cyan]Gathering all case data for reporting...[/cyan]")
                        all_results, primary_target = get_all_case_results(conn)
                        if not all_results: console.print("[yellow]No results in case to report on.[/yellow]"); continue
                        all_results = apply_ner_analysis(all_results)
                        report_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filenames = {"json": f"report_{case_name}_{report_timestamp}.json", "graph": f"graph_{case_name}_{report_timestamp}.html", "html": f"REPORT_{case_name.upper()}_{report_timestamp}.html"}
                        generate_interactive_graph(all_results, primary_target, filenames["graph"])
                        generate_html_report(all_results, primary_target, filenames)
                        console.print(f"\n[bold green]✓✓✓ Master interactive HTML report saved to [bold]{filenames['html']}[/bold][/green]")
                    elif action == "3": break
            finally:
                if conn: conn.close()

if __name__ == "__main__":
    main()
