import unittest

from signalscope.core import PortFinding, guess_service_name, infer_os_hint, parse_ports, parse_targets


class ParsePortsTests(unittest.TestCase):
    def test_range_and_discrete_ports(self):
        self.assertEqual(parse_ports("22,80,1000-1002"), [22, 80, 1000, 1001, 1002])

    def test_duplicate_ports_are_removed(self):
        self.assertEqual(parse_ports("80,80,79-81"), [79, 80, 81])

    def test_invalid_range_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("100-10")


class ParseTargetsTests(unittest.TestCase):
    def test_targets_are_flattened_and_deduplicated(self):
        self.assertEqual(
            parse_targets(["127.0.0.1, localhost", "127.0.0.1"]),
            ["127.0.0.1", "localhost"],
        )

    def test_cidr_targets_are_expanded(self):
        self.assertEqual(
            parse_targets(["192.168.1.0/30"]),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_cidr_expansion_respects_max_hosts(self):
        with self.assertRaises(ValueError):
            parse_targets(["192.168.1.0/24"], max_hosts=8)


class GuessServiceTests(unittest.TestCase):
    def test_banner_takes_priority(self):
        self.assertEqual(guess_service_name(5001, "SSH-2.0-OpenSSH_9.6"), "SSH")

    def test_known_port_is_used_when_banner_is_empty(self):
        self.assertEqual(guess_service_name(443, ""), "HTTPS")


class OsHintTests(unittest.TestCase):
    def test_windows_ports_produce_windows_hint(self):
        findings = [
            PortFinding(port=135, state="OPEN", service="MSRPC", latency_ms=1.0),
            PortFinding(port=445, state="OPEN", service="SMB", latency_ms=1.2),
            PortFinding(port=3389, state="OPEN", service="RDP", latency_ms=2.1),
        ]
        family, confidence, evidence = infer_os_hint(findings)
        self.assertEqual(family, "Windows")
        self.assertIn(confidence, {"medium", "high"})
        self.assertTrue(evidence)

    def test_linux_banner_produces_linux_hint(self):
        findings = [
            PortFinding(port=22, state="OPEN", service="SSH", latency_ms=0.9, banner="SSH-2.0-OpenSSH_9.6 Ubuntu"),
            PortFinding(port=5432, state="OPEN", service="POSTGRESQL", latency_ms=1.1),
        ]
        family, confidence, evidence = infer_os_hint(findings)
        self.assertEqual(family, "Linux/Unix")
        self.assertTrue(evidence)


if __name__ == "__main__":
    unittest.main()
