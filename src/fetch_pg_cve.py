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
    {"version": "9.6", "eol": True},
    {"version": "9.5", "eol": True},
    {"version": "9.4", "eol": True},
    {"version": "9.3", "eol": True},
    {"version": "9.2", "eol": True},
    {"version": "9.1", "eol": True},
    {"version": "9.0", "eol": True},
    {"version": "8.4", "eol": True}
]

# "Yanked" releases
YANKED_VERSIONS = {
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
    "9.3.3": "Serious affecting 9.3 only.",
    "9.3.2": "Serious affecting 9.3 only.",
    "9.3.1": "Serious affecting 9.3 only.",
    "9.3.0": "Serious affecting 9.3 only.",
    "9.2.1": "Planner regression in strict join clauses.",
    "9.2.0": "Planner regression in strict join clauses.",
    "6.6.6": "Diabolic bug."
}

# CVE with known Exploits
KNOWN_EXPLOITS = [
    "CVE-2025-1094",   # SQLi in psql/libpq, RCE; exploited in the wild
    "CVE-2024-10979",  # PL/Perl arbitrary code execution
    "CVE‑2023‑2454",   # Arbitrary code execution via CREATE SCHEMA
    "CVE-2022-1552",   # Autovacuum privilege escalation; exploited in the wild
    "CVE‑2020‑25695",  # SQL injection in PostgreSQL
    "CVE-2019-10130",  # Tablesampler security bypass
    "CVE‑2019‑9193",   # COPY TO/FROM PROGRAM, RCE; exploited in the wild; used in pentests
    "CVE‑2018‑10915",  # PL/Perl arbitrary code execution; used in pentests
    "CVE‑2018‑1115",   # COPY input validation
    "CVE-2017-14798",  # SUSE privilege escalation (not a PG CVE)
    "CVE‑2017‑8806",   # PL/Python code execution; used in pentests
    "CVE‑2016‑5729",   # Buffer overflow in seg; used in pentests 
    "CVE-2009-0922",   # Multiple vulnerabilities
    "CVE-2005-0245",   # Conversion Encoding Remote DOS
    "CVE‑1970‑0000"    # Epoch placeholder
]

# Other CVE related to PostgreSQL
# CVE-2025-13780	PgAdmin, RCE
# CVE-2026-9082		Drupal Core SQL Injection Vulnerability


# ==========================================
# UTILS
# ==========================================
def get_all_minor_releases(major):
    """ NOTICE: TO BE UPGRADED every 3 months """
    if major == "18": max_minor = 4
    elif major == "17": max_minor = 10
    elif major == "16": max_minor = 14
    elif major == "15": max_minor = 18
    elif major == "14": max_minor = 23
    elif major == "13": max_minor = 23
    elif major == "12": max_minor = 22
    elif major == "11": max_minor = 22
    elif major == "10": max_minor = 23
    elif major == "9.6": return [f"9.6.{i}" for i in range(25)]  # one more
    elif major == "9.5": return [f"9.5.{i}" for i in range(26)]
    elif major == "9.4": return [f"9.4.{i}" for i in range(27)]
    elif major == "9.3": return [f"9.3.{i}" for i in range(26)]
    elif major == "9.2": return [f"9.2.{i}" for i in range(25)]
    elif major == "9.1": return [f"9.1.{i}" for i in range(25)]
    elif major == "9.0": return [f"9.0.{i}" for i in range(24)]
    elif major == "8.4": return [f"8.4.{i}" for i in range(22)]
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
        "cve_matrix": cve_matrix
    }

if __name__ == "__main__":
    data = fetch_and_parse_cves()
    if data:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] Output file '{OUTPUT_FILE}' compiled and unified.")