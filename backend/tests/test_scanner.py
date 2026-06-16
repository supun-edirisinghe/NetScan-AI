"""
tests/test_scanner.py
─────────────────────
Unit tests for the port scanner and AI analyzer.
Run: pytest tests/ -v
"""
import pytest
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.services.scanner import (
    parse_port_range, expand_targets, PORT_RISK_WEIGHTS, KNOWN_SERVICES
)
from app.services.ai_analyzer import (
    calculate_risk_score, generate_recommendations, analyze_scan_with_ml
)


# ── Scanner unit tests ─────────────────────────────────────────────────────

class TestPortRangeParsing:
    def test_simple_range(self):
        ports = parse_port_range("1-5")
        assert ports == [1, 2, 3, 4, 5]

    def test_single_port(self):
        ports = parse_port_range("80")
        assert ports == [80]

    def test_comma_separated(self):
        ports = parse_port_range("80,443,8080")
        assert sorted(ports) == [80, 443, 8080]

    def test_mixed(self):
        ports = parse_port_range("1-3,80,443")
        assert sorted(ports) == [1, 2, 3, 80, 443]

    def test_dedup(self):
        ports = parse_port_range("1-5,3-7")
        assert len(ports) == len(set(ports))


class TestTargetExpansion:
    def test_single_ip(self):
        hosts = expand_targets("192.168.1.1")
        assert "192.168.1.1" in hosts

    def test_cidr_slash32(self):
        hosts = expand_targets("192.168.1.1/32")
        assert len(hosts) >= 1

    def test_small_cidr(self):
        hosts = expand_targets("192.168.1.0/30")
        # /30 has 2 usable hosts
        assert len(hosts) >= 1

    def test_hostname(self):
        hosts = expand_targets("localhost")
        assert "localhost" in hosts

    def test_multiple_targets(self):
        hosts = expand_targets("192.168.1.1, 10.0.0.1")
        assert len(hosts) == 2

    def test_large_network_raises(self):
        with pytest.raises(ValueError, match="too large"):
            expand_targets("10.0.0.0/8")


class TestKnownServices:
    def test_ssh_known(self):
        assert KNOWN_SERVICES[22] == "SSH"

    def test_http_known(self):
        assert KNOWN_SERVICES[80] == "HTTP"

    def test_telnet_high_risk(self):
        assert PORT_RISK_WEIGHTS[23] >= 0.9

    def test_https_low_risk(self):
        assert PORT_RISK_WEIGHTS[443] <= 0.2


# ── AI Analyzer unit tests ─────────────────────────────────────────────────

class TestRiskScoring:
    def make_host(self, ports):
        return {
            "open_ports": [
                {"port": p, "service": KNOWN_SERVICES.get(p, "unknown"),
                 "risk_weight": PORT_RISK_WEIGHTS.get(p, 0.2)}
                for p in ports
            ]
        }

    def test_no_ports_is_zero_risk(self):
        score, level = calculate_risk_score({"open_ports": []})
        assert score == 0.0
        assert level == "low"

    def test_telnet_is_critical(self):
        host = self.make_host([23])
        score, level = calculate_risk_score(host)
        assert level in ("high", "critical")

    def test_smb_is_critical(self):
        host = self.make_host([445])
        score, level = calculate_risk_score(host)
        assert level in ("high", "critical")

    def test_https_only_is_low(self):
        host = self.make_host([443])
        score, level = calculate_risk_score(host)
        assert level == "low"
        assert score < 25

    def test_many_critical_ports_is_critical(self):
        host = self.make_host([23, 445, 3389, 6379, 27017])
        score, level = calculate_risk_score(host)
        assert level == "critical"
        assert score >= 70

    def test_score_between_0_and_100(self):
        host = self.make_host(list(PORT_RISK_WEIGHTS.keys()))
        score, _ = calculate_risk_score(host)
        assert 0 <= score <= 100


class TestRecommendations:
    def make_scan(self, ports):
        return {
            "hosts": [{"open_ports": [{"port": p} for p in ports]}]
        }

    def test_telnet_triggers_r001(self):
        recs = generate_recommendations(self.make_scan([23]))
        ids = [r["id"] for r in recs]
        assert "R001" in ids

    def test_smb_triggers_r003(self):
        recs = generate_recommendations(self.make_scan([445]))
        ids = [r["id"] for r in recs]
        assert "R003" in ids

    def test_safe_scan_has_minimal_recs(self):
        recs = generate_recommendations(self.make_scan([443, 80]))
        for r in recs:
            assert r["severity"] not in ("critical",)

    def test_recs_sorted_by_severity(self):
        recs = generate_recommendations(self.make_scan([23, 445, 3389, 22, 80]))
        severities = [r["severity"] for r in recs]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        scores = [order[s] for s in severities]
        assert scores == sorted(scores)

    def test_no_duplicate_recommendations(self):
        recs = generate_recommendations(self.make_scan([23, 23, 23]))
        ids = [r["id"] for r in recs]
        assert len(ids) == len(set(ids))


class TestFullAnalysis:
    def test_full_pipeline(self):
        scan_result = {
            "target": "192.168.1.1",
            "total_hosts": 1,
            "hosts_up": 1,
            "total_open_ports": 3,
            "port_distribution": {"23": 1, "80": 1, "443": 1},
            "hosts": [
                {
                    "host": "192.168.1.1",
                    "ip": "192.168.1.1",
                    "status": "up",
                    "open_ports": [
                        {"port": 23, "service": "Telnet", "risk_weight": 0.95},
                        {"port": 80, "service": "HTTP",   "risk_weight": 0.20},
                        {"port": 443, "service": "HTTPS", "risk_weight": 0.10},
                    ]
                }
            ]
        }

        result = analyze_scan_with_ml(scan_result)

        assert "overall_risk_score" in result
        assert "overall_risk_level" in result
        assert "ai_recommendations" in result
        assert "high_risk_hosts" in result
        assert result["overall_risk_level"] in ("low", "medium", "high", "critical")
        assert 0 <= result["overall_risk_score"] <= 100
        assert isinstance(result["ai_recommendations"], list)
        assert len(result["ai_recommendations"]) > 0

        # Telnet should trigger a critical recommendation
        crit_recs = [r for r in result["ai_recommendations"] if r["severity"] == "critical"]
        assert len(crit_recs) > 0
