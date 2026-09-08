# 🐘 PG_CVE - PostgreSQL CVE & Release Intelligence
**Version 1.0.7** &nbsp; [![CI](https://github.com/meob/PG_CVE/actions/workflows/ci.yml/badge.svg)](https://github.com/meob/PG_CVE/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**PG_CVE** is a lightweight tool designed to provide an immediate overview of CVEs (Common Vulnerabilities and Exposures) and the stability of PostgreSQL releases.

---

## 🎯 Objectives
- **Simplicity:** Provide a static HTML dashboard with no server-side dependencies.
- **Precision:** Integrate automatic scraping with manual expert curation to identify real-world exploits and serious regression bugs.
- **Decision Support:** Assist DBAs in deciding if and when to upgrade a specific installation.

---

## 🌐 Live Dashboard & Usage
The interactive dashboard is publicly available at the following address:
👉 **[PostgreSQL CVE Dashboard](https://meob.github.io/PG_CVE/)**

### Searching by Version (Deep-linking)
You can query a specific PostgreSQL version directly via the `version` URL parameter. This is useful for linking directly to a version's security status from other documentation or reports:
- `https://meob.github.io/PG_CVE/?version=15.8`

---

## 📂 Project Structure
- `src/`: Contains the Python script for scraping and data generation.
- `src/find_exploits.py`: Exploit finder/verifier that sweeps CISA KEV, GitHub (level-0 repos) and Exploit-DB/Sploitus for public PoCs of PostgreSQL CVEs, reporting each exploit's publication date and flagging any not yet curated.
- `src/validate_data.py`: Structural validator for the generated JSON (used by CI).
- `src/test_fetch_pg_cve.py`: Offline unit tests for the parser logic.
- `src/test_find_exploits.py`: Offline unit tests for the exploit finder logic.
- `.github/workflows/ci.yml`: CI checks (syntax, tests, validation) run on every push and pull request.
- `docs/`: Contains the web dashboard (HTML/JS) and JSON data. This folder is ready to be served via **GitHub Pages**.
- `requirements.txt`: Python dependencies required for the scraper.

---

## 🛠️ Operation and Usage

### 1. Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configuration and Manual Curation
The script `src/fetch_pg_cve.py` contains sections that require human intervention to ensure the absence of false positives:
- `YANKED_VERSIONS`: Versions that have critical bugs or regressions (e.g., data corruption).
- `KNOWN_EXPLOITS`: A list of CVEs for which a public exploit is confirmed to exist.
- `TRACKED_MAJORS`: List of supported major versions and EOL status.
- `RELEASE_DATES`: Official release dates for each minor version, scraped from PostgreSQL documentation.

To avoid *missing* an exploit, run the verifier `src/find_exploits.py` periodically
or on every release day: it cross-checks the curated `KNOWN_EXPLOITS` against
CISA KEV, GitHub repositories named after each PostgreSQL CVE, and
Exploit-DB/Sploitus (best-effort), reporting the publication date of every
finding and exiting `1` when a new candidate needs human review.

```bash
python src/find_exploits.py --years 3          # ~6 min sweep of the last 3 years
python src/find_exploits.py --all-cves         # every historical CVE (slow)
```

### 3. Data Generation
Run the script every 3 months or upon the release of new security advisories:
```bash
python src/fetch_pg_cve.py
```
This will generate/update the `docs/postgresql_cves.json` file.

> 💡 **Note for Forks:** This site includes an Umami analytics script. If you host your own version, please remove the script or replace the `data-website-id` with your own to keep our traffic data separate.

### 4. Release-Day Procedure
When a new minor release + security advisory drops, follow the step-by-step checklist in [RELEASE_RUNBOOK.md](RELEASE_RUNBOOK.md): curate `YANKED_VERSIONS`/`KNOWN_EXPLOITS`, regenerate, verify, commit and publish.

### 5. CI & Validation
A GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push and pull request:

- **Syntax check:** `py_compile` on all Python sources.
- **Unit tests:** offline tests (stdlib `unittest`) for the parser logic.
- **Data validation:** `src/validate_data.py` verifies the structure of `docs/postgresql_cves.json` (consistent majors, well-formed CVE entries, unique CVE ids, valid CVSS range, non-empty yanked reasons, valid release dates).

Run the same checks locally:
```bash
python -m py_compile src/fetch_pg_cve.py src/find_exploits.py src/validate_data.py src/test_fetch_pg_cve.py src/test_find_exploits.py
python -m unittest discover -s src -p "test_*.py"
python src/validate_data.py docs/postgresql_cves.json
```

---

## ✨ Recent Updates (v1.0.3 .. v1.0.7)
- **v1.0.7 Exploits Update & Exploit Finder:** Five CVEs with public exploits added to `KNOWN_EXPLOITS`. Fixed a latent bug that silently disabled the `known_exploit` flag for some CVEs. New `src/find_exploits.py` verifier using CISA KEV, GitHub level-0 repos and Exploit-DB/Sploitus for PostgreSQL exploits.
- **v1.0.6 Exploit-aware Ordering & Exploits Update:** CVEs with a known public exploit are now ranked first in the dashboard, ahead of CVEs sorted by raw CVSS score. Bundled with the known-exploits update marking CVE-2026-14669 as exploited.
- **v1.0.5 Release Dates:** Added official release dates for all tracked minor versions. Dates are displayed next to the minor version selector in the dashboard. The `release_dates` field is included in the generated JSON and validated by CI.
- **Aug 2026 Data Update:** New minors `18.6 / 17.11 / 16.15 / 15.19 / 14.24` ingested. PostgreSQL 18.5 was skipped (never released, regression discovered post-wrap) and is flagged as a yanked release in the dashboard.
- **Deep-linking Support:** Added the ability to select a specific version via URL parameter (e.g., `index.html?version=15.3`). The dashboard now automatically filters and renders the CVE status for the requested version upon loading.
- **Web Analytics:** Added tracking on GitHub Pages. [Umami](https://github.com/umami-software/umami) is a simple, fast, privacy-focused, Open Source Web Analytic tool.
- **CI & Validation:** Added a GitHub Actions workflow with syntax checks, offline unit tests and JSON data validation. New `RELEASE_RUNBOOK.md` documents the release-day procedure.

---

## 🚀 Future Ideas
Ideas under consideration — not necessarily planned. Some were implemented (see Recent Updates), others may never be:

1.  **Dynamic Update Timestamp:** Automate the "Last updated" date in the HTML by pulling it from a new `last_updated` field in the generated JSON.
2.  ~~**Major Release Metadata:** Enrich the `major_versions` data with release dates and support status to provide context on the lifecycle of each major branch.~~ ✅ Done in v1.0.5 (release dates only).
3.  **Semi-automatic Minor Auto-discovery:** Implement a function to suggest new minor versions detected on the official website.
4.  **GitHub Actions Integration:** Create a workflow that runs scraping periodically and opens a *Pull Request* with new data.
5.  **Export Formats:** Add generation of reports in Markdown or CSV format.

---

## 🧠 Development Notes

This project was developed through iterative collaboration with generative AI tools. AI assistance was used for implementation, refactoring, and debugging, while overall design decisions, customization, validation, and final integration were performed by the author.

---

## 🔗 Links and References
The original project and the live version are curated by Meo:
- [Live Dashboard](https://www.meo.bogliolo.name/white/oracle/pg_cve.htm) - Legacy CVE list (since PG 8.4)
- [Your PostgreSQL Stinks!](https://www.meo.bogliolo.name/white/unix/trans.htm#post) - PostgreSQL Release Overview.
- [Personal Website (EN)](https://www.meo.bogliolo.name/en/)

External references:
- [OpenCVE.io (PostgreSQL)](https://app.opencve.io/cve/?vendor=postgresql) - Excellent detailed CVE records.

---

## 📜 License
Distributed under the **Apache 2.0** license. See the `LICENSE` file for details.
