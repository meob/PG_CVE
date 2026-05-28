# 🐘 PG_CVE - PostgreSQL CVE & Release Intelligence
**Version 1.0.2**

**PG_CVE** is a lightweight tool designed to provide an immediate overview of CVEs (Common Vulnerabilities and Exposures) and the stability of PostgreSQL releases.

---

## ✨ Recent Updates (v1.0.2)
- **Deep-linking Support:** Added the ability to select a specific version via URL parameter (e.g., `index.html?version=15.3`). The dashboard now automatically filters and renders the CVE status for the requested version upon loading.

---

## 🎯 Objectives
- **Simplicity:** Provide a static HTML dashboard with no server-side dependencies.
- **Precision:** Integrate automatic scraping with manual expert curation to identify real-world exploits and serious regression bugs.
- **Decision Support:** Assist DBAs in deciding if and when to upgrade a specific installation.

---

## 📂 Project Structure
- `src/`: Contains the Python script for scraping and data generation.
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

### 3. Data Generation
Run the script every 3 months or upon the release of new security advisories:
```bash
python src/fetch_pg_cve.py
```
This will generate/update the `docs/postgresql_cves.json` file.

---

## 🚀 Proposed Optimizations (Roadmap)
The following improvements are planned for future versions, maintaining the manual validation approach:

1.  **Dynamic Update Timestamp:** Automate the "Last updated" date in the HTML by pulling it from a new `last_updated` field in the generated JSON.
2.  **Major Release Metadata:** Enrich the `major_versions` data with release dates and support status to provide context on the lifecycle of each major branch.
3.  **Semi-automatic Minor Auto-discovery:** Implement a function to suggest new minor versions detected on the official website.
4.  **GitHub Actions Integration:** Create a workflow that runs scraping periodically and opens a *Pull Request* with new data.
5.  **Export Formats:** Add generation of reports in Markdown or CSV format.

---

## 🧠 Development Notes

This project was developed through iterative collaboration with generative AI tools. AI assistance was used for implementation, refactoring, and debugging, while overall design decisions, customization, validation, and final integration were performed by the author.

---

## 🔗 Links and References
The original project and the live version are curated by Meo:
- [Live Dashboard](https://www.meo.bogliolo.name/white/oracle/pg_cve.htm)
- [Your PostgreSQL Stinks!](https://www.meo.bogliolo.name/white/unix/trans.htm#post) - PostgreSQL Release Overview.
- [Personal Website (EN)](https://www.meo.bogliolo.name/en/)

External references:
- [OpenCVE.io (PostgreSQL)](https://app.opencve.io/cve/?vendor=postgresql) - Excellent detailed CVE records.

---

## 📜 License
Distributed under the **Apache 2.0** license. See the `LICENSE` file for details.
