"""Unit tests for exposure evaluation engine and built-in rules."""

import pytest

from reconforge.assessment.engine import ExposureEngine
from reconforge.assessment.models import ExposureRuleDefinition, RuleCondition
from reconforge.core.enums import (
    FindingCategory,
    ObservationConfidence,
    PortState,
    SeverityLevel,
)
from reconforge.core.models import PortObservation
from reconforge.fingerprinting.models import ServiceFingerprint


@pytest.fixture
def engine() -> ExposureEngine:
    return ExposureEngine(include_builtin=True)


def test_builtin_rules_loaded(engine: ExposureEngine):
    rules = engine.list_rules()
    assert len(rules) >= 15
    rule_ids = {r.id for r in rules}
    assert "EXP-CLEARTEXT-TELNET" in rule_ids
    assert "EXP-CLEARTEXT-FTP" in rule_ids
    assert "EXP-CLEARTEXT-HTTP" in rule_ids
    assert "EXP-MGMT-SSH" in rule_ids
    assert "EXP-DB-REDIS" in rule_ids
    assert "EXP-DB-MYSQL" in rule_ids
    assert "EXP-DB-POSTGRES" in rule_ids
    assert "EXP-MGMT-DOCKER" in rule_ids
    assert "EXP-TLS-EXPIRED" in rule_ids
    assert "EXP-TLS-LEGACY" in rule_ids


def test_telnet_exposure_matching(engine: ExposureEngine):
    rule = engine.get_rule("EXP-CLEARTEXT-TELNET")
    assert rule is not None

    # Match by port 23
    matched, reasons = engine.evaluate_service(
        rule=rule,
        port=23,
        protocol="tcp",
        service_name="unknown",
    )
    assert matched is True
    assert "port=23" in reasons

    # Match on non-standard port by service name
    matched_svc, reasons_svc = engine.evaluate_service(
        rule=rule,
        port=2323,
        protocol="tcp",
        service_name="telnet",
    )
    assert matched_svc is True
    assert "service_name=telnet" in reasons_svc

    # Non-matching service
    matched_false, _ = engine.evaluate_service(
        rule=rule,
        port=80,
        protocol="tcp",
        service_name="http",
    )
    assert matched_false is False


def test_tls_conditions_evaluation(engine: ExposureEngine):
    expired_rule = engine.get_rule("EXP-TLS-EXPIRED")
    assert expired_rule is not None

    # Expired cert triggers
    matched, reasons = engine.evaluate_service(
        rule=expired_rule,
        port=443,
        protocol="tcp",
        tls_metadata={"is_expired": True, "is_self_signed": False},
    )
    assert matched is True
    assert "tls_certificate_expired" in reasons

    # Valid cert does not trigger
    matched_valid, _ = engine.evaluate_service(
        rule=expired_rule,
        port=443,
        protocol="tcp",
        tls_metadata={"is_expired": False, "is_self_signed": False},
    )
    assert matched_valid is False

    # Deprecated protocol triggers EXP-TLS-LEGACY
    legacy_rule = engine.get_rule("EXP-TLS-LEGACY")
    assert legacy_rule is not None
    matched_legacy, reasons_legacy = engine.evaluate_service(
        rule=legacy_rule,
        port=443,
        protocol="tcp",
        tls_metadata={"protocol_version": "TLSv1.0"},
    )
    assert matched_legacy is True
    assert any("TLSv1.0" in r for r in reasons_legacy)

    # Modern TLS 1.3 does not trigger legacy rule
    matched_modern, _ = engine.evaluate_service(
        rule=legacy_rule,
        port=443,
        protocol="tcp",
        tls_metadata={"protocol_version": "TLSv1.3"},
    )
    assert matched_modern is False


def test_banner_pattern_evaluation(engine: ExposureEngine):
    banner_rule = engine.get_rule("EXP-INFO-BANNER")
    assert banner_rule is not None

    matched, reasons = engine.evaluate_service(
        rule=banner_rule,
        port=22,
        protocol="tcp",
        banner_snippet="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    )
    assert matched is True
    assert any("banner_regex_match" in r for r in reasons)


def test_require_all_condition(engine: ExposureEngine):
    custom_rule = ExposureRuleDefinition(
        id="EXP-CUSTOM-STRICT",
        name="Strict Multi-Condition Rule",
        description="Requires port 8080 AND http service name AND tomcat product.",
        severity=SeverityLevel.HIGH,
        category=FindingCategory.MISCONFIGURATION,
        conditions=RuleCondition(
            ports=[8080],
            service_names=["http"],
            products=["tomcat"],
            require_all=True,
        ),
        remediation="Restrict tomcat access.",
    )
    engine.register_rule(custom_rule)

    # Partial match: port 8080 and http, but product is nginx -> must NOT match
    matched_partial, _ = engine.evaluate_service(
        rule=custom_rule,
        port=8080,
        protocol="tcp",
        service_name="http",
        product="nginx",
    )
    assert matched_partial is False

    # Full match: port 8080, http, tomcat -> MUST match
    matched_full, reasons = engine.evaluate_service(
        rule=custom_rule,
        port=8080,
        protocol="tcp",
        service_name="http",
        product="Apache Tomcat",
    )
    assert matched_full is True
    assert len(reasons) == 3  # port, service_name, product


def test_evaluate_observations_to_findings(engine: ExposureEngine):
    obs = [
        PortObservation(
            target_ip="192.168.1.100",
            port=6379,
            state=PortState.OPEN,
            response_time_ms=1.5,
            service=ServiceFingerprint(
                service_name="redis",
                product="Redis key-value store",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
        PortObservation(
            target_ip="192.168.1.100",
            port=80,
            state=PortState.CLOSED,
        ),
    ]

    findings = engine.evaluate_observations(
        assessment_id="test-ass-1",
        asset_id="test-asset-1",
        observations=obs,
    )

    assert len(findings) >= 1
    redis_finding = next((f for f in findings if f.rule_id == "EXP-DB-REDIS"), None)
    assert redis_finding is not None
    assert redis_finding.severity == SeverityLevel.HIGH
    assert redis_finding.evidence["port"] == 6379
    assert redis_finding.evidence["service_name"] == "redis"
