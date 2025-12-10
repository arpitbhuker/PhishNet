# PhishNet — Suspicious Link Analyzer

PhishNet is a compact rule-based suspicious link analyzer with a lightweight Flask web UI. It extracts URL features and applies deterministic rules to produce an interpretable phishing risk score and explanation.

## Features
- URL parsing and heuristic feature extraction (domain, tokens, IP-in-host, length, redirects).
- Rule-based scoring engine with human-readable explanations.
- Simple web UI (Flask) and API endpoint for integration.
- Packaging support (PyInstaller spec) for creating distributable executables.

## Repo structure

PhishNet/
├─ app.py                 # Flask app entry (routes, UI rendering)
├─ server.py              # Alternative server entry / WSGI start
├─ phishnet_core.py       # Rule-based analyzer & scoring logic
├─ features_extractor.py  # Functions that extract features from URL
├─ launcher.py/.spec      # Packaging helper / PyInstaller spec
├─ requirements.txt       # Python dependencies (place exact file here)
├─ README.md              # (this file — add to repo)
├─ run.bat.txt            # Windows quick run hints
├─ templates/             # Flask Jinja2 templates (index.html / result pages)
├─ static/                # CSS / JS / images for frontend
├─ assets/                # icons / additional assets
├─ build/ dist/           # Build artifacts (if packaging supported)
└─ __pycache__/

## Output
<img width="1919" height="951" alt="Output" src="https://github.com/user-attachments/assets/62fe1435-f20f-4a18-bd15-3b864eee37f9" />

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/arpitbhuker/PhishNet.git
cd PhishNet
```

### 2. Set Up Virtual Environment & Install Dependencies
```bash
python -m venv .venv
```

- Activate the environment:
Windows
```bash
.venv\Scripts\activate
```
macOS / Linux
```bash
source .venv/bin/activate
```

- Install required packages
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python app.py
# or
python server.py 
```

### 4. Open the Web Interface

Visit:
```bash
http://127.0.0.1:5000/
```

## Architecture diagram (text + explanation)
                      +------------------+
                      |   Browser / UI   |
                      | (templates/static)|
                      +--------+---------+
                               |
                        HTTP  | POST / GET
                               v
                      +--------+---------+
                      |   Flask server   |  (app.py / server.py)
                      |  routes + API    |
                      +--------+---------+
                               |
                               v
                      +--------+---------+
                      | phishnet_core.py |  (scoring/rule-engine)
                      +--------+---------+
                               |
                               v
                      +--------+---------+
                      | features_extractor.py |
                      | (parsing & heuristics)|
                      +-----------------------+


Flow: UI → Flask route receives URL → features_extractor parses & returns features → phishnet_core scores and returns verdict & explanation → UI shows results.


## 🔍 How It Works — Technical Summary

### 1. Feature Extraction (`features_extractor.py`)
The system begins by decomposing and analyzing the submitted URL.  
Core operations include:

- Parsing the URL into `domain`, `subdomain`, `path`, and query parameters.
- Detecting:
  - Presence of **IP addresses** in place of domain names.
  - **Abnormally long URLs** or excessively long paths.
  - **Multiple subdomains** (often used in phishing redirects).
  - **Suspicious tokens** such as:  
    `login`, `update`, `secure`, `verify`, `confirm`, `account`, etc.
  - **Unicode or homoglyph substitutions** meant to mimic real domains.
  - **Multiple redirects** or unusual URL encoding.
  - **Low-reputation or uncommon TLDs**.
- Uses simple regex checks, Python `urllib` utilities, and optionally `tldextract`.

The output is a structured feature dictionary consumed by the scoring engine.

---

### 2. Rule-Based Scoring (`phishnet_core.py`)
Each extracted feature maps to a predefined rule and weight.  
Examples of rule mappings:

| Feature Detected               | Score Impact |
|-------------------------------|--------------|
| `has_ip_in_domain`            | `+3`         |
| `contains_suspicious_token`   | `+2`         |
| `url_length > 75`             | `+1`         |
| `reputable_tld`               | `-1`         |

The scoring engine:

1. Aggregates weights from all matched rules.  
2. Computes a **final phishing score**.  
3. Maps that score to a category:  
   - **Benign**  
   - **Suspicious**  
   - **Phishing**
4. Returns:
   - The numeric score  
   - The textual verdict  
   - A full explanation of which rules triggered

This keeps the model explainable without needing ML.

---

### 3. Web UI / API Layer (`app.py`, `templates/`)
The Flask layer provides both a frontend and optional backend API.

- **Web interface** renders:
  - URL input form
  - Detailed analysis results
  - Highlighted risk indicators
- **API endpoint** (if enabled):
  - `/api/analyze` or `/predict`
  - Accepts JSON payload `{ "url": "..." }`
  - Returns analyzed features, score, and verdict

This makes PhishNet usable both as a standalone
