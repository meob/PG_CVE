"""Structural validator for docs/postgresql_cves.json.

Exits with a non-zero code and prints every problem found. Used by CI.
"""

import json
import re
import sys

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
VERSION_RE = re.compile(r"^\d+(\.\d+)*$")
REQUIRED_CVE_FIELDS = ("id", "cvss", "known_exploit", "summary", "link")
REQUIRED_MAJOR_FIELDS = ("version", "eol")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate(data):
    errors = []

    if data.get("database") != "PostgreSQL":
        errors.append("'database' must be 'PostgreSQL'.")

    majors = data.get("major_versions")
    if not isinstance(majors, list) or not majors:
        errors.append("'major_versions' must be a non-empty list.")
        majors = []

    matrix = data.get("cve_matrix")
    if not isinstance(matrix, dict) or not matrix:
        errors.append("'cve_matrix' must be a non-empty object.")
        matrix = {}

    major_set = set()
    for major in majors:
        if not all(k in major for k in REQUIRED_MAJOR_FIELDS):
            errors.append(f"Invalid major_versions entry: {major!r}")
            continue
        version = major["version"]
        major_set.add(version)
        if not VERSION_RE.match(version):
            errors.append(f"Major '{version}' is not a valid version string.")
        if not isinstance(major["eol"], bool):
            errors.append(f"Major '{version}': 'eol' must be a boolean.")

    for version in matrix:
        if version not in major_set:
            errors.append(f"cve_matrix contains orphan major '{version}'.")
    for version in major_set:
        if version not in matrix:
            errors.append(f"cve_matrix is missing major '{version}'.")

    for major, minors in matrix.items():
        if not isinstance(minors, dict):
            errors.append(f"Major '{major}': cve_matrix value must be an object.")
            continue
        for minor, cves in minors.items():
            if not VERSION_RE.match(minor):
                errors.append(f"Major '{major}': invalid minor '{minor}'.")
            if not minor.startswith(major):
                errors.append(f"Major '{major}': minor '{minor}' does not start with the major.")
            if not isinstance(cves, list):
                errors.append(f"Major '{major}' minor '{minor}': CVE list must be an array.")
                continue
            seen = set()
            for entry in cves:
                if not isinstance(entry, dict):
                    errors.append(f"Major '{major}' minor '{minor}': CVE entry must be an object.")
                    continue
                cve_id = entry.get("id", "")
                if not CVE_RE.match(cve_id):
                    errors.append(f"Major '{major}' minor '{minor}': invalid CVE id {cve_id!r}.")
                elif cve_id in seen:
                    errors.append(f"Major '{major}' minor '{minor}': duplicate CVE {cve_id}.")
                seen.add(cve_id)
                for field in REQUIRED_CVE_FIELDS:
                    if field not in entry:
                        errors.append(
                            f"Major '{major}' minor '{minor}': missing field '{field}' in {cve_id or '?'}."
                        )
                cvss = entry.get("cvss")
                if not isinstance(cvss, (int, float)) or not (0 <= cvss <= 10):
                    errors.append(f"Major '{major}' minor '{minor}': invalid CVSS {cvss!r} for {cve_id}.")
                if not isinstance(entry.get("known_exploit"), bool):
                    errors.append(
                        f"Major '{major}' minor '{minor}': 'known_exploit' must be boolean for {cve_id}."
                    )
                for field in ("summary", "link"):
                    value = entry.get(field)
                    if not isinstance(value, str) or not value:
                        errors.append(
                            f"Major '{major}' minor '{minor}': '{field}' must be a non-empty string for {cve_id}."
                        )

    yanked = data.get("yanked_versions", {})
    if not isinstance(yanked, dict):
        errors.append("'yanked_versions' must be an object.")
    else:
        for version, reason in yanked.items():
            if not isinstance(reason, str) or not reason.strip():
                errors.append(f"yanked_versions[{version!r}]: reason must be a non-empty string.")

    release_dates = data.get("release_dates", {})
    if not isinstance(release_dates, dict):
        errors.append("'release_dates' must be an object.")
    else:
        for version, date in release_dates.items():
            if not VERSION_RE.match(version):
                errors.append(f"release_dates: invalid version key {version!r}.")
            if not isinstance(date, str) or not DATE_RE.match(date):
                errors.append(f"release_dates[{version!r}]: date must be YYYY-MM-DD, got {date!r}.")
        for major, minors in matrix.items():
            if not isinstance(minors, dict):
                continue
            for minor in minors:
                if minor in yanked:
                    continue
                if minor not in release_dates:
                    errors.append(f"release_dates: missing entry for {minor!r}.")

    return errors


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-json>")
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[!] File not found: {sys.argv[1]}")
        return 1
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON in {sys.argv[1]}: {exc}")
        return 1

    errors = validate(data)
    if errors:
        print(f"[!] Validation failed with {len(errors)} problem(s):")
        for err in errors:
            print(f"  - {err}")
        return 1
    print("[+] Validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
