# 🚀 PG_CVE Release-Day Runbook

Step-by-step procedure to publish PostgreSQL CVE data on the day a new minor
release + security advisory drops (second Thursday of February, May, August,
November).

**Goal:** from advisory published to live dashboard update in minutes, without
losing manual curation work.

---

## 0. Why this exists

The scraper (`src/fetch_pg_cve.py`) regenerates `docs/postgresql_cves.json` from
scratch every run. Three things are NOT scraped and must be curated by hand:

| Knob | Location | Purpose |
|------|----------|---------|
| `TRACKED_MAJORS` | script header | which major branches exist + EOL flag |
| `YANKED_VERSIONS` | script header | releases recalled/withdrawn (serious bugs) |
| `KNOWN_EXPLOITS` | script header | CVEs with confirmed public exploits |

If these drift from the curated `docs/postgresql_cves.json`, a regeneration
silently destroys manual edits. Keep them in sync (see §3).

---

## 1. Pre-release preparation (a few days before)

1. Read the current data in the JSON to know the baseline.
2. Bump `max_minor` in `get_all_minor_releases()` (`src/fetch_pg_cve.py:88`)
   for every **active** major so the upcoming minors exist in the matrix:
   - current cycle → `18.5 / 17.11 / 16.15 / 15.19 / 14.24`
   - example: `if major == "18": max_minor = 5`
   - EOL majors keep their last value (e.g. `13` stays `23`).
3. Sync `TRACKED_MAJORS` and `YANKED_VERSIONS` with the curated JSON, so a
   regeneration does not revert manual edits.
4. Regenerate once and verify the new minors appear with empty CVE lists.

## 2. Release day (when the advisory is public)

1. **Read the advisory** on <https://www.postgresql.org/support/security/>
   (or the news announcement). Note:
   - the new minor versions (should match the prepped ones);
   - the new CVE IDs + CVSS scores + affected/fixed ranges.
2. **New major out?** (e.g. PostgreSQL 19 in Sept/Oct 2026) → add it to
   `TRACKED_MAJORS` with `"eol": false`.
3. **Major reached EOL?** → flip its `"eol"` flag to `true` in `TRACKED_MAJORS`.
4. **Check `YANKED_VERSIONS`:** if the freshly released minor was pulled
   (e.g. "serious bugs introduced for the fix to some CVEs"), add it here with
   the reason. This drives the warning banner in the dashboard.
5. **Check `KNOWN_EXPLOITS`:** add any new CVE with a confirmed public exploit.
   Keep the comment explaining the exploit.
6. **Regenerate the data** (see §4). The new CVEs are picked up automatically
   from the security page and distributed to every affected minor.
7. **Verify** (see §5). In particular confirm the new CVEs appear under the new
   minors and that the fixed-in ranges look right.
8. **Bump version/date metadata** in `docs/index.html`
   (`itemprop="dateModified"` + `Version:` + `Last updated`).
9. **Commit and push.** GitHub Pages deploys `docs/` automatically; the live
   dashboard updates at <https://meob.github.io/PG_CVE/>.

## 3. Keep script and curated JSON in sync

The JSON holds the single source of truth for manual curation. When you edit
`TRACKED_MAJORS`, `YANKED_VERSIONS` or `KNOWN_EXPLOITS` in the JSON *by hand*,
mirror the change into the script header too — otherwise the next run reverts
it. After a sync, a regeneration should produce **zero unexpected diff** on the
JSON beyond the intended change.

## 4. Regenerate

```bash
source .venv/bin/activate
python src/fetch_pg_cve.py
```

Output: `docs/postgresql_cves.json` (overwritten).

## 5. Verification checklist

```bash
# Quick structural check: majors, last minor, CVE count per major
python -c "
import json
d = json.load(open('docs/postgresql_cves.json'))
print('majors:', [m['version'] for m in d['major_versions']])
for m in d['cve_matrix']:
    ms = sorted(d['cve_matrix'][m], key=lambda s: tuple(int(x) for x in s.replace(m,'').strip('.').split('.') if x))
    n = sum(len(v) for v in d['cve_matrix'][m].values())
    print(m, 'last:', ms[-1], '| cve entries:', n)
"
```

- `git diff --stat docs/postgresql_cves.json` → expected scope only (new
  versions, new CVEs, sync changes). No silent data loss on old minors.
- New minors show CVEs; previous latest minors lost the just-fixed CVEs.
- Spot-check a deep-link: `https://meob.github.io/PG_CVE/?version=<new-minor>`.

## 6. Release calendar (as of Aug 2026)

| Event | Date |
|-------|------|
| PostgreSQL 18.5 / 17.11 / 16.15 / 15.19 / 14.24 | Aug 13, 2026 |
| PostgreSQL 19.0 (add to `TRACKED_MAJORS`) | ~Sep/Oct 2026 |
| PostgreSQL 14 EOL (flip `eol: true`) | Nov 2026 |

---

## 7. Roadmap notes

- **Semi-automatic minor auto-discovery** (roadmap item #3) would eliminate
  step 1.2 entirely by deriving new minors from the official site. Not yet
  implemented; this runbook is the manual fallback.
- GitHub Actions scheduled scraping (roadmap item #4) would automate §2.6 and
  open a PR with the regenerated data for human review.
