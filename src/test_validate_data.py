"""Offline unit tests for the JSON structural validator."""

import copy
import unittest

import validate_data as v


def base_data():
    return {
        "database": "PostgreSQL",
        "last_updated": "2026-11-12",
        "major_versions": [{"version": "14", "eol": True}],
        "cve_matrix": {"14": {"14.25": []}},
        "yanked_versions": {},
        "release_dates": {"14.25": "2026-11-12"},
    }


class TestValidateData(unittest.TestCase):
    def test_valid_data(self):
        self.assertEqual(v.validate(base_data()), [])

    def test_missing_last_updated(self):
        data = base_data()
        del data["last_updated"]
        errors = v.validate(data)
        self.assertTrue(any("last_updated" in error for error in errors))

    def test_invalid_last_updated(self):
        data = base_data()
        data["last_updated"] = "12/11/2026"
        errors = v.validate(data)
        self.assertTrue(any("last_updated" in error for error in errors))

    def test_missing_release_date(self):
        data = base_data()
        data["release_dates"] = {}
        errors = v.validate(data)
        self.assertTrue(any("release_dates" in error for error in errors))

    def test_invalid_cvss(self):
        data = copy.deepcopy(base_data())
        data["cve_matrix"]["14"]["14.25"] = [{
            "id": "CVE-2026-12345",
            "cvss": 11.0,
            "known_exploit": False,
            "summary": "test",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        }]
        errors = v.validate(data)
        self.assertTrue(any("invalid CVSS" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
