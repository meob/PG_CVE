import json
import re
import requests
from bs4 import BeautifulSoup
from packaging.version import Version

# ==========================================
# CONF
# ==========================================
TARGET_URL = "https://www.postgresql.org/support/security/"
OUTPUT_FILE = "docs/postgresql_cves.json"

# Major versions and EOL
TRACKED_MAJORS = [
    {"version": "18", "eol": False},
    {"version": "17", "eol": False},
    {"version": "16", "eol": False},
    {"version": "15", "eol": False},
    {"version": "14", "eol": False},
    {"version": "13", "eol": True},
    {"version": "12", "eol": True},
    {"version": "11", "eol": True},
    {"version": "10", "eol": True},
    {"version": "9.6", "eol": True}
]

# "Yanked" releases
YANKED_VERSIONS = {
    "18.5": "Never released, due to a regression discovered post-wrap.",
    "18.2": "Serious bugs introduced for the fix to some CVEs.",
    "17.8": "Serious bugs introduced for the fix to some CVEs.",
    "16.12": "Serious bugs introduced for the fix to some CVEs.",
    "15.16": "Serious bugs introduced for the fix to some CVEs.",
    "15.0": "Disk space leak when dropping large (multi‑file) tables.",
    "14.21": "Serious bugs introduced for the fix to some CVEs.",
    "14.3": "Data corruption using CONCURRENTLY.",
    "14.2": "Data corruption using CONCURRENTLY.",
    "14.1": "Data corruption using CONCURRENTLY.",
    "14.0": "Data corruption using CONCURRENTLY.",
    "13.1": "substring() misbehavior with invalid/negative length.",
    "13.0": "substring() misbehavior with invalid/negative length.",
    "12.1": "Query planner regression on partitioned tables.",
    "11.2": "JIT compiler regression causing backend server crash.",
    "9.5.1": "Bug on text indexes optimization.",
    "9.5.0": "Bug on text indexes optimization.",
    "9.4.0": "Bug affecting 9.4 only.",
    "9.3.3": "Serious bug affecting 9.3 only.",
    "9.3.2": "Serious bug affecting 9.3 only.",
    "9.3.1": "Serious bug affecting 9.3 only.",
    "9.3.0": "Serious bug affecting 9.3 only and regression in pg_subtrans on hot standby.",
    "9.2.5": "Regression in pg_subtrans on hot standby.",
    "9.2.1": "Planner regression in strict join clauses.",
    "9.2.0": "Planner regression in strict join clauses.",
    "9.1.10": "Regression in pg_subtrans on hot standby.",
    "9.0.14": "Regression in pg_subtrans on hot standby.",
    "6.6.6": "Diabolic bug."
}

# Release dates scraped from official PostgreSQL documentation
RELEASE_DATES = {
    "9.6.0": "2016-09-29",
    "9.6.1": "2016-10-27",
    "9.6.2": "2017-02-09",
    "9.6.3": "2017-05-11",
    "9.6.4": "2017-08-10",
    "9.6.5": "2017-08-31",
    "9.6.6": "2017-11-09",
    "9.6.7": "2018-02-08",
    "9.6.8": "2018-03-01",
    "9.6.9": "2018-05-10",
    "9.6.10": "2018-08-09",
    "9.6.11": "2018-11-08",
    "9.6.12": "2019-02-14",
    "9.6.13": "2019-05-09",
    "9.6.14": "2019-06-20",
    "9.6.15": "2019-08-08",
    "9.6.16": "2019-11-14",
    "9.6.17": "2020-02-13",
    "9.6.18": "2020-05-14",
    "9.6.19": "2020-08-13",
    "9.6.20": "2020-11-12",
    "9.6.21": "2021-02-11",
    "9.6.22": "2021-05-13",
    "9.6.23": "2021-08-12",
    "9.6.24": "2021-11-11",
    "10.0": "2017-10-05",
    "10.1": "2017-11-09",
    "10.2": "2018-02-08",
    "10.3": "2018-03-01",
    "10.4": "2018-05-10",
    "10.5": "2018-08-09",
    "10.6": "2018-11-08",
    "10.7": "2019-02-14",
    "10.8": "2019-05-09",
    "10.9": "2019-06-20",
    "10.10": "2019-08-08",
    "10.11": "2019-11-14",
    "10.12": "2020-02-13",
    "10.13": "2020-05-14",
    "10.14": "2020-08-13",
    "10.15": "2020-11-12",
    "10.16": "2021-02-11",
    "10.17": "2021-05-13",
    "10.18": "2021-08-12",
    "10.19": "2021-11-11",
    "10.20": "2022-02-10",
    "10.21": "2022-05-12",
    "10.22": "2022-08-11",
    "10.23": "2022-11-10",
    "11.0": "2018-10-18",
    "11.1": "2018-11-08",
    "11.2": "2019-02-14",
    "11.3": "2019-05-09",
    "11.4": "2019-06-20",
    "11.5": "2019-08-08",
    "11.6": "2019-11-14",
    "11.7": "2020-02-13",
    "11.8": "2020-05-14",
    "11.9": "2020-08-13",
    "11.10": "2020-11-12",
    "11.11": "2021-02-11",
    "11.12": "2021-05-13",
    "11.13": "2021-08-12",
    "11.14": "2021-11-11",
    "11.15": "2022-02-10",
    "11.16": "2022-05-12",
    "11.17": "2022-08-11",
    "11.18": "2022-11-10",
    "11.19": "2023-02-09",
    "11.20": "2023-05-11",
    "11.21": "2023-08-10",
    "11.22": "2023-11-09",
    "12.0": "2019-10-03",
    "12.1": "2019-11-14",
    "12.2": "2020-02-13",
    "12.3": "2020-05-14",
    "12.4": "2020-08-13",
    "12.5": "2020-11-12",
    "12.6": "2021-02-11",
    "12.7": "2021-05-13",
    "12.8": "2021-08-12",
    "12.9": "2021-11-11",
    "12.10": "2022-02-10",
    "12.11": "2022-05-12",
    "12.12": "2022-08-11",
    "12.13": "2022-11-10",
    "12.14": "2023-02-09",
    "12.15": "2023-05-11",
    "12.16": "2023-08-10",
    "12.17": "2023-11-09",
    "12.18": "2024-02-08",
    "12.19": "2024-05-09",
    "12.20": "2024-08-08",
    "12.21": "2024-11-14",
    "12.22": "2024-11-21",
    "13.0": "2019-09-24",
    "13.1": "2020-11-12",
    "13.2": "2021-02-11",
    "13.3": "2021-05-13",
    "13.4": "2021-08-12",
    "13.5": "2021-11-11",
    "13.6": "2022-02-10",
    "13.7": "2022-05-12",
    "13.8": "2022-08-11",
    "13.9": "2022-11-10",
    "13.10": "2023-02-09",
    "13.11": "2023-05-11",
    "13.12": "2023-08-10",
    "13.13": "2023-11-09",
    "13.14": "2024-02-08",
    "13.15": "2024-05-09",
    "13.16": "2024-08-08",
    "13.17": "2024-11-14",
    "13.18": "2024-11-21",
    "13.19": "2025-02-13",
    "13.20": "2025-02-20",
    "13.21": "2025-05-08",
    "13.22": "2025-08-14",
    "13.23": "2025-11-13",
    "14.0": "2021-09-30",
    "14.1": "2021-11-11",
    "14.2": "2022-02-10",
    "14.3": "2022-05-12",
    "14.4": "2022-06-16",
    "14.5": "2022-08-11",
    "14.6": "2022-11-10",
    "14.7": "2023-02-09",
    "14.8": "2023-05-11",
    "14.9": "2023-08-10",
    "14.10": "2023-11-09",
    "14.11": "2024-02-08",
    "14.12": "2024-05-09",
    "14.13": "2024-08-08",
    "14.14": "2024-11-14",
    "14.15": "2024-11-21",
    "14.16": "2025-02-13",
    "14.17": "2025-02-20",
    "14.18": "2025-05-08",
    "14.19": "2025-08-14",
    "14.20": "2025-11-13",
    "14.21": "2026-02-12",
    "14.22": "2026-02-26",
    "14.23": "2026-05-14",
    "14.24": "2026-08-13",
    "15.0": "2022-10-13",
    "15.1": "2022-11-10",
    "15.2": "2023-02-09",
    "15.3": "2023-05-11",
    "15.4": "2023-08-10",
    "15.5": "2023-11-09",
    "15.6": "2024-02-08",
    "15.7": "2024-05-09",
    "15.8": "2024-08-08",
    "15.9": "2024-11-14",
    "15.10": "2024-11-21",
    "15.11": "2025-02-13",
    "15.12": "2025-02-20",
    "15.13": "2025-05-08",
    "15.14": "2025-08-14",
    "15.15": "2025-11-13",
    "15.16": "2026-02-12",
    "15.17": "2026-02-26",
    "15.18": "2026-05-14",
    "15.19": "2026-08-13",
    "16.0": "2023-09-14",
    "16.1": "2023-11-09",
    "16.2": "2024-02-08",
    "16.3": "2024-05-09",
    "16.4": "2024-08-08",
    "16.5": "2024-11-14",
    "16.6": "2024-11-21",
    "16.7": "2025-02-13",
    "16.8": "2025-02-20",
    "16.9": "2025-05-08",
    "16.10": "2025-08-14",
    "16.11": "2025-11-13",
    "16.12": "2026-02-12",
    "16.13": "2026-02-26",
    "16.14": "2026-05-14",
    "16.15": "2026-08-13",
    "17.0": "2024-09-26",
    "17.1": "2024-11-14",
    "17.2": "2024-11-21",
    "17.3": "2025-02-13",
    "17.4": "2025-02-20",
    "17.5": "2025-05-08",
    "17.6": "2025-08-14",
    "17.7": "2025-11-13",
    "17.8": "2026-02-12",
    "17.9": "2026-02-26",
    "17.10": "2026-05-14",
    "17.11": "2026-08-13",
    "18.0": "2025-09-25",
    "18.1": "2025-11-13",
    "18.2": "2026-02-12",
    "18.3": "2026-02-26",
    "18.4": "2026-05-14",
    "18.6": "2026-08-13",
}

# CVE with known Exploits
KNOWN_EXPLOITS = [
    # 2026
    "CVE-2026-14669",  # PoC Code Enables RCE in PostgreSQL
    "CVE-2026-14662",  # tsvector/tsquery integer wraparound -> OOB write, RCE; PoC 2026-09-01
    "CVE-2026-6471",   # PostGREShell: logical-decoding dlopen() arbitrary file, RCE; PoC 2026-09-05
    "CVE-2026-2005",   # pgcrypto heap buffer overflow -> RCE; PoC 2026-05-13
    # 2025
    "CVE-2025-1094",   # SQLi in psql/libpq, RCE; exploited in the wild
    "CVE-2025-8714",   # pg_dump untrusted data -> RCE in psql client; PoC 2025-10-20
    "CVE-2025-8715",   # pg_dump newline injection -> RCE + SQLi as superuser; PoC 2025-10-20
    # 2024
    "CVE-2024-10979",  # PL/Perl arbitrary code execution
    "CVE-2024-0985",   # REFRESH MVIEW CONCURRENTLY privilege escalation; PoC 2024-03-19
    # 2023
    "CVE-2023-2454",   # Arbitrary code execution via CREATE SCHEMA
    # 2022
    "CVE-2022-1552",   # Autovacuum privilege escalation; exploited in the wild
    # 2020
    "CVE-2020-25695",  # SQL injection in PostgreSQL
    # 2019
    "CVE-2019-10130",  # Tablesampler security bypass
    "CVE-2019-9193",   # COPY TO/FROM PROGRAM, RCE; exploited in the wild; used in pentests
    # 2018
    "CVE-2018-10915",  # PL/Perl arbitrary code execution; used in pentests
    "CVE-2018-1115",   # COPY input validation
    # 2017
    "CVE-2017-14798",  # SUSE privilege escalation (not a PG CVE)
    "CVE-2017-8806",   # PL/Python code execution; used in pentests
    # 2016
    "CVE-2016-5729",   # Buffer overflow in seg; used in pentests
    # older
    "CVE-2009-0922",   # Multiple vulnerabilities
    "CVE-2005-0245",   # Conversion Encoding Remote DOS
    "CVE-1970-0000"    # Epoch placeholder
]

# Other CVE related to PostgreSQL
# CVE-2025-13780	PgAdmin, RCE
# CVE-2026-9082		Drupal Core SQL Injection Vulnerability


# ==========================================
# UTILS
# ==========================================
def get_all_minor_releases(major):
    """ NOTICE: TO BE UPGRADED every 3 months """
    if major == "18": max_minor = 6
    elif major == "17": max_minor = 11
    elif major == "16": max_minor = 15
    elif major == "15": max_minor = 19
    elif major == "14": max_minor = 24
    elif major == "13": max_minor = 23
    elif major == "12": max_minor = 22
    elif major == "11": max_minor = 22
    elif major == "10": max_minor = 23
    elif major == "9.6": return [f"9.6.{i}" for i in range(25)]  # one more
    else: max_minor = 23
    return [f"{major}.{i}" for i in range(max_minor + 1)]

def clean_cve_id(text):
    match = re.search(r'(CVE-\d{4}-\d+)', text)
    return match.group(1) if match else None

def parse_affected_range(affected_str, major):
    """Analizza i range di versioni gestiti da PostgreSQL (es: '15.0 - 15.3')."""
    affected_str = affected_str.strip()
    if "All versions" in affected_str:
        return lambda v: True

    if " - " in affected_str:
        try:
            start_part, end_part = affected_str.split(" - ")
            v_start = Version(start_part.strip())
            v_end = Version(end_part.strip())
            return lambda v: v_start <= v <= v_end
        except Exception:
            pass

    return lambda v: major in affected_str


# ==========================================
# CORE SCRAPER & PARSER
# ==========================================
def fetch_and_parse_cves():
    print(f"[*] Fetching security data from master source {TARGET_URL}...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    try:
        response = requests.get(TARGET_URL, headers=headers)
        if response.status_code != 200:
            print(f"[!] Error: Main page unreachable (Status: {response.status_code})")
            return None
    except Exception as e:
        print(f"[!] Network Error: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')
    content_table = soup.find('table')
    if not content_table:
        print("[!] Error: HTML Structure changed. Table not found.")
        return None

    # Inizializzazione matrice strutturata
    cve_matrix = {}
    major_list_for_json = []
    
    for item in TRACKED_MAJORS:
        major = item["version"]
        major_list_for_json.append({"version": major, "eol": item["eol"]})
        cve_matrix[major] = {}
        for minor in get_all_minor_releases(major):
            cve_matrix[major][minor] = []

    rows = content_table.find_all('tr')
    print(f"[*] Parsing {len(rows)} data streams against vulnerability vectors...")
    cve_count = 0

    for row in rows:
        cells = row.find_all('td')
        if len(cells) < 4:
            continue
            
        raw_cve = cells[0].text.strip()
        cve_id = clean_cve_id(raw_cve)
        if not cve_id:
            continue
            
        affected_str = cells[1].text.strip()
        fixed_in_str = cells[2].text.strip()
        summary = cells[4].text.strip().replace("more details", "").strip() if len(cells) > 4 else ""
        cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Pulizia del punteggio CVSS
        cvss_text = re.sub(r'[^\d.]', '', cells[3].text.strip())
        try:
            cvss_score = float(cvss_text) if cvss_text else 0.0
        except ValueError:
            cvss_score = 0.0

        # Controllo se l'exploit è presente nella lista KNOWN_EXPLOITS
        has_known_exploit = True if cve_id in KNOWN_EXPLOITS else False

        # Distribuzione dei dati nella matrice
        for item in TRACKED_MAJORS:
            major = item["version"]
            
            if major not in affected_str and "All versions" not in affected_str and major not in fixed_in_str:
                continue

            range_checker = parse_affected_range(affected_str, major)

            for minor in cve_matrix[major].keys():
                try:
                    v_minor = Version(minor)
                    is_vulnerable = False

                    # 1. Controlla se la versione rientra nel range iniziale dei vulnerabili
                    if range_checker(v_minor):
                        is_vulnerable = True
                    
                    # 2. NUOVA LOGICA: Cerca la patch corretta per questo specifico ramo major
                    if fixed_in_str:
                        # Splitta la stringa se ci sono più fix (es: "18.4, 17.10, 16.14")
                        all_fixes = [f.strip() for f in fixed_in_str.split(",")]
                        
                        # Trova se esiste una patch specifica per il ramo corrente (es: inizia con "17.")
                        specific_fix = next((f for f in all_fixes if f.startswith(major + ".")), None)
                        
                        if specific_fix:
                            v_fix = Version(specific_fix)
                            # Se la minor esaminata è uguale o successiva alla patch, NON è vulnerabile
                            if v_minor >= v_fix:
                                is_vulnerable = False

                    if is_vulnerable:
                        cve_entry = {
                            "id": cve_id,
                            "cvss": cvss_score,
                            "known_exploit": has_known_exploit,
                            "summary": f"[Fixed in {fixed_in_str if fixed_in_str else 'N/A'}] {summary}",
                            "link": cve_link
                        }
                        if cve_entry not in cve_matrix[major][minor]:
                            cve_matrix[major][minor].append(cve_entry)
                            cve_count += 1
                except Exception:
                    continue

    print(f"[+] Intelligence compilation complete: {cve_count} active target points mapped.")

    return {
        "database": "PostgreSQL",
        "major_versions": major_list_for_json,
        "yanked_versions": YANKED_VERSIONS,
        "release_dates": RELEASE_DATES,
        "cve_matrix": cve_matrix
    }

if __name__ == "__main__":
    data = fetch_and_parse_cves()
    if data:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] Output file '{OUTPUT_FILE}' compiled and unified.")