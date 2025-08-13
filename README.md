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
> # BioDaemon

BioDaemon is an advanced OSINT and cyber reconnaissance toolkit with a cyberpunk-themed UI powered by Rich. It combines API-based and API-free recon techniques, automates data correlation, and generates interactive visual reports.

## Features

### Core OSINT Capabilities
- Username Recon – Checks multiple platforms for a given username.
- Email OSINT – Breach lookup, pattern analysis, disposable email detection.
- Phone OSINT – Carrier, location, and number reputation checks.
- Image Analysis – EXIF → GPS, optional reverse image search (API or free).
- LinkedIn Search – No API scraping support.
- GitHub Dorking – Finds exposed code/assets without API.
- Pastebin Search – No API required.
- DuckDuckGo Search – API-free with result parsing.
- Google Dork Builder – Build and execute custom dorks.

### Infrastructure & Network Recon
- Shodan & Censys integration (optional API).
- GeoIP Lookup – IP → Country, ASN, provider.
- Wayback Machine – Historical site snapshots.
- DNS Enumeration – Subdomains, records, resolvers.

### Data Processing & Analysis
- Natural Language Processing (NER) – Extracts entities from text.
- SQLite + FTS5 – Fast local case database with full-text search.
- Artifact Manager – Store and view all retrieved OSINT artifacts.

### Reporting
- HTML Interactive Graph – Network/entity visualization (PyVis).
- GeoMap – Folium-based mapping of geolocated data.
- GEXF Export – For Gephi or other graph tools.
- PDF Reports – Optional WeasyPrint rendering.
- Session Artifacts Viewer – All results in one place.

## Cyberpunk UI
BioDaemon uses Rich for a neon-style cyberpunk interface:
- Animated spinners
- High-contrast cyberpunk colors
- Live progress bars
- Real-time status panels

## Installation
git clone https://github.com/wickednull/BioDaemon.git

cd BioDaemon

pip install -r requirements.txt

python biodaemon.py

First run will auto-install dependencies if missing.

## Quick Start
Run BioDaemon in interactive mode:
python biodaemon.py

Run a single recon task from CLI:
python biodaemon.py --username targetuser --quick-recon

## Configuration
Edit config.json to store optional API keys for:
- Shodan
- Censys
- Reverse Image Search
- Other integrations

If keys are not set, BioDaemon falls back to API-free methods where possible.

## Example Use Cases
- Track a username across dozens of sites
- Investigate leaked credentials from Pastebin
- Map historical site changes via Wayback Machine
- Locate exposed source code on GitHub
- Geolocate images from EXIF metadata
- Build a social network graph from OSINT data

## Legal & Ethical Use
BioDaemon is intended only for ethical, authorized testing and research.
You are responsible for ensuring compliance with all laws in your jurisdiction.

## License
MIT License – See LICENSE file for details.
