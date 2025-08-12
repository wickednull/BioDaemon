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
> 
Key Features
 * 🗃️ Case Management: Don't lose your work. Create, load, and manage investigations in a persistent SQLite database.
 * ⚡ Concurrent & Modular: Runs multiple OSINT modules simultaneously for rapid data collection.
 * 🧠 Intelligence Analysis: Automatically performs Named Entity Recognition (NER) to extract people, organizations, and locations from unstructured text.
 * 🌐 Multi-Vector Collection: Gathers data from a wide array of sources:
   * Username availability across dozens of sites.
   * Social media profiles (Twitter, Reddit, Instagram).
     <!-- end list -->
   * HaveIBeenPwned data breach lookups.
   * Domain WHOIS and DNS record analysis.
   * Image EXIF and geolocation data.
 * 📊 Interactive Reporting: Generates a single, comprehensive HTML report with embedded, interactive relationship graphs (pyvis) and maps (folium).
 * 🕵️ Anonymity Focused: Optional integration with the Tor network to mask investigator activity.
⚠️ Disclaimer
This tool is intended for educational purposes and authorized security research only. The user is responsible for all actions performed with this tool. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always respect privacy and obtain explicit, written permission before conducting an investigation on any target.
Architectural Workflow
BioDaemon is designed as an intelligence platform, not just a script. The data flows through a structured analysis pipeline.
graph TD
    A[OSINT Modules] -->|Collect Raw Data| B(Case Database);
    B -->|Load All Case Data| C{Analysis Engine};
    C -->|NER & Sentiment| D[Correlated Intelligence];
    D --> E[Interactive HTML Report];

Installation
BioDaemon is designed to be run on a Linux environment, preferably a security-focused distribution like Kali Linux or Parrot OS.
1. Prerequisites
 * Python 3.9 or higher
 * pip and git
2. Clone the Repository
git clone https://github.com/YourUsername/BioDaemon.git
cd BioDaemon

3. Install Dependencies
The script will attempt to auto-install dependencies on the first run. However, it's recommended to install them first.
pip install -r requirements.txt

(Note: A requirements.txt file should be created from the final script's dependencies for this to work.)
4. Download NLP Model
BioDaemon uses the spaCy library for Natural Language Processing. You must download its language model:
python -m spacy download en_core_web_sm

Configuration
Before running, you must create a credentials.json file in the same directory. This file stores your API keys and login credentials, keeping them separate from the code.
credentials.json Template:
{
  "twitter": {
    "bearer_token": "YOUR_BEARER_TOKEN",
    "api_key": "YOUR_API_KEY",
    "api_secret": "YOUR_API_SECRET",
    "access_token": "YOUR_ACCESS_TOKEN",
    "access_secret": "YOUR_ACCESS_SECRET"
  },
  "instagram": {
    "username": "YOUR_INSTAGRAM_USERNAME",
    "password": "YOUR_INSTAGRAM_PASSWORD"
  },
  "reddit": {
    "client_id": "YOUR_REDDIT_CLIENT_ID",
    "client_secret": "YOUR_REDDIT_CLIENT_SECRET",
    "user_agent": "BioDaemon v1.0 by YourName"
  },
  "hibp": {
    "api_key": "YOUR_HAVEIBEENPWNED_API_KEY"
  }
}

Usage Workflow
Run the script from your terminal:
python biodaemon_v1.0.py

Step 1: Case Management
You will first be prompted to create a new case or load an existing one. Each case is a separate database file in the /cases directory.
Step 2: Investigation Menu
Once a case is active, you have two main options:
 * Run Investigation Modules: Select from the list of available OSINT modules to gather new data. The results will be automatically saved to your active case file.
 * Generate Full Case Report: When you are ready to analyze your findings, select this option. BioDaemon will query all data ever collected for the case, perform NER analysis, and generate the final reports.
Step 3: Review Your Report
After generation, you will find three files in the main directory:
 * REPORT_[CaseName]_[Timestamp].html: The master interactive HTML report. Open this in your browser.
 * graph_[CaseName]_[Timestamp].html: The standalone interactive relationship graph.
 * report_[CaseName]_[Timestamp].json: The raw, consolidated JSON data.
Modules Overview
| Module Name | Required Input Type | Description |
|---|---|---|
| Username Availability | username | Checks for a username across dozens of popular websites. |
| Domain WHOIS/DNS | domain | Fetches registration and DNS records for a domain. |
| Twitter | username | Gathers profile info and recent tweets. |
| Reddit | username | Gathers profile info, recent posts, and comments. |
| HaveIBeenPwned | email | Checks if an email address has appeared in known breaches. |
| EXIF Geolocation | local file path | Extracts GPS metadata from an image file. |
| Google Dorking | search term | Runs advanced Google searches to find linked accounts/docs. |
License
This project is licensed under the MIT License. See the LICENSE file for details.
