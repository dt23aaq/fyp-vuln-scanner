import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "code"))

from scanner_core import ServiceRecord, match_vulnerabilities, parse_nmap_xml


class ScannerCoreTests(unittest.TestCase):
    def test_bundled_scan_has_stable_open_service_count(self):
        services, metadata = parse_nmap_xml("scans/metasploitable-scan.xml")
        self.assertEqual(len(services), 30)
        self.assertEqual(metadata["scanner"], "nmap")
        self.assertTrue(all(service.state == "open" for service in services))

    def test_rule_requires_version_when_rule_is_version_specific(self):
        service = ServiceRecord("192.0.2.1", 21, "tcp", "open", "ftp", "vsftpd", "3.0.5")
        self.assertEqual(match_vulnerabilities([service]), [])

    def test_port_only_heuristic_is_marked_as_such(self):
        service = ServiceRecord("192.0.2.1", 1524, "tcp", "open", "unknown", "", "")
        matches = match_vulnerabilities([service])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1].evidence_type, "port-heuristic")

    def test_malformed_xml_raises_parse_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml") as source:
            source.write("<nmaprun>")
            source.flush()
            with self.assertRaises(Exception):
                parse_nmap_xml(source.name)


if __name__ == "__main__":
    unittest.main()
