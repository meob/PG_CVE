"""Offline unit tests for the pure logic in fetch_pg_cve.py.

Run from the repository root with:
    python -m unittest discover -s src -p "test_*.py"
"""

import unittest

import fetch_pg_cve as f


class TestCleanCveId(unittest.TestCase):
    def test_extracts_id(self):
        self.assertEqual(f.clean_cve_id("CVE-2026-6637"), "CVE-2026-6637")
        self.assertEqual(f.clean_cve_id("CVE-2026-6637 more details"), "CVE-2026-6637")
        self.assertEqual(f.clean_cve_id("[CVE-2025-1094]"), "CVE-2025-1094")

    def test_no_match(self):
        self.assertIsNone(f.clean_cve_id(""))
        self.assertIsNone(f.clean_cve_id("no cve here"))


class TestParseAffectedRange(unittest.TestCase):
    def test_all_versions(self):
        checker = f.parse_affected_range("All versions", "14")
        self.assertTrue(checker(f.Version("8.0")))
        self.assertTrue(checker(f.Version("18.0")))

    def test_version_range(self):
        checker = f.parse_affected_range("15.0 - 15.3", "15")
        self.assertTrue(checker(f.Version("15.0")))
        self.assertTrue(checker(f.Version("15.3")))
        self.assertTrue(checker(f.Version("15.2")))
        self.assertFalse(checker(f.Version("15.4")))
        self.assertFalse(checker(f.Version("14.9")))

    def test_major_scope(self):
        checker = f.parse_affected_range("18, 17, 16", "17")
        self.assertTrue(checker(f.Version("17.9")))
        other = f.parse_affected_range("18, 17, 16", "15")
        self.assertFalse(other(f.Version("15.0")))


class TestGetAllMinorReleases(unittest.TestCase):
    def test_active_majors(self):
        self.assertEqual(f.get_all_minor_releases("18")[-1], "18.5")
        self.assertEqual(len(f.get_all_minor_releases("18")), 6)
        self.assertEqual(f.get_all_minor_releases("17")[-1], "17.11")
        self.assertEqual(f.get_all_minor_releases("16")[-1], "16.15")
        self.assertEqual(f.get_all_minor_releases("15")[-1], "15.19")
        self.assertEqual(f.get_all_minor_releases("14")[-1], "14.24")

    def test_legacy_majors(self):
        self.assertEqual(len(f.get_all_minor_releases("9.6")), 25)
        self.assertEqual(f.get_all_minor_releases("9.6")[-1], "9.6.24")
        self.assertEqual(f.get_all_minor_releases("13")[-1], "13.23")

    def test_unknown_major_defaults(self):
        releases = f.get_all_minor_releases("99")
        self.assertEqual(len(releases), 24)


if __name__ == "__main__":
    unittest.main()
