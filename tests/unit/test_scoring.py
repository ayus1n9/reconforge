"""Unit tests for attack-surface scoring algorithm and risk prioritization."""

import pytest

from reconforge.core.enums import (
    AssetCriticality,
    FindingCategory,
    RiskPriority,
    SeverityLevel,
)
from reconforge.inventory.repository import AssetRepository
from reconforge.scoring.calculator import AttackSurfaceCalculator
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import (
    AssessmentRecord,
    AssetRecord,
    FindingRecord,
    ServiceRecord,
)


class TestPriorityMapping:
    """Validate deterministic priority assignment (P1 to P5)."""

    def test_cisa_kev_always_p1(self) -> None:
        """Any finding with is_known_exploited must yield P1 regardless of criticality."""
        for crit in AssetCriticality:
            priority = AttackSurfaceCalculator.get_finding_priority(
                severity=SeverityLevel.MEDIUM,
                asset_criticality=crit,
                is_known_exploited=True,
            )
            assert priority == RiskPriority.P1

    def test_critical_severity_asset_dependency(self) -> None:
        """Critical findings map to P1 on High/Critical assets, and P2 on Medium/Low assets."""
        assert (
            AttackSurfaceCalculator.get_finding_priority(
                severity=SeverityLevel.CRITICAL,
                asset_criticality=AssetCriticality.CRITICAL,
            )
            == RiskPriority.P1
        )
        assert (
            AttackSurfaceCalculator.get_finding_priority(
                severity=SeverityLevel.CRITICAL,
                asset_criticality=AssetCriticality.HIGH,
            )
            == RiskPriority.P1
        )
        assert (
            AttackSurfaceCalculator.get_finding_priority(
                severity=SeverityLevel.CRITICAL,
                asset_criticality=AssetCriticality.MEDIUM,
            )
            == RiskPriority.P2
        )
        assert (
            AttackSurfaceCalculator.get_finding_priority(
                severity=SeverityLevel.CRITICAL,
                asset_criticality=AssetCriticality.LOW,
            )
            == RiskPriority.P2
        )

    def test_high_severity_always_p2(self) -> None:
        """High severity findings map to P2."""
        for crit in [AssetCriticality.CRITICAL, AssetCriticality.MEDIUM, AssetCriticality.LOW]:
            priority = AttackSurfaceCalculator.get_finding_priority(
                severity=SeverityLevel.HIGH,
                asset_criticality=crit,
            )
            assert priority == RiskPriority.P2

    def test_database_exposure_elevation(self) -> None:
        """Database exposure findings elevate to P2."""
        priority = AttackSurfaceCalculator.get_finding_priority(
            severity=SeverityLevel.MEDIUM,
            asset_criticality=AssetCriticality.MEDIUM,
            category=FindingCategory.DATABASE_EXPOSURE,
        )
        assert priority == RiskPriority.P2

    def test_medium_low_informational_priorities(self) -> None:
        """Standard severity mapping for P3, P4, and P5."""
        assert AttackSurfaceCalculator.get_finding_priority(SeverityLevel.MEDIUM) == RiskPriority.P3
        assert AttackSurfaceCalculator.get_finding_priority(SeverityLevel.LOW) == RiskPriority.P4
        assert (
            AttackSurfaceCalculator.get_finding_priority(SeverityLevel.INFORMATIONAL)
            == RiskPriority.P5
        )


class TestRiskLevelMapping:
    """Validate score to qualitative rating mapping."""

    def test_score_to_risk_level_thresholds(self) -> None:
        calc = AttackSurfaceCalculator()
        assert calc.score_to_risk_level(95.0) == "CRITICAL"
        assert calc.score_to_risk_level(80.0) == "CRITICAL"
        assert calc.score_to_risk_level(79.9) == "HIGH"
        assert calc.score_to_risk_level(60.0) == "HIGH"
        assert calc.score_to_risk_level(59.9) == "MEDIUM"
        assert calc.score_to_risk_level(35.0) == "MEDIUM"
        assert calc.score_to_risk_level(34.9) == "LOW"
        assert calc.score_to_risk_level(10.0) == "LOW"
        assert calc.score_to_risk_level(9.9) == "NEGLIGIBLE"
        assert calc.score_to_risk_level(0.0) == "NEGLIGIBLE"


class TestAssetScoring:
    """Validate mathematical scoring formulas, multipliers, and clamping."""

    def test_clean_asset_zero_score(self) -> None:
        calc = AttackSurfaceCalculator()
        asset = AssetRecord(id="ast-1", ip_address="192.168.1.50", criticality="medium")
        score_res = calc.calculate_asset_score(asset, services=[], findings=[])

        assert score_res.score == 0.0
        assert score_res.risk_level == "NEGLIGIBLE"
        assert score_res.top_priority == RiskPriority.P5
        assert score_res.breakdown.exposure_base == 0.0
        assert score_res.breakdown.findings_subtotal == 0.0

    def test_exposure_base_calculation(self) -> None:
        calc = AttackSurfaceCalculator()
        asset = AssetRecord(id="ast-1", ip_address="192.168.1.50", criticality="medium")
        services = [
            ServiceRecord(id="s1", asset_id="ast-1", port=22, service_name="ssh"),
            ServiceRecord(id="s2", asset_id="ast-1", port=6379, service_name="redis"),
            ServiceRecord(id="s3", asset_id="ast-1", port=23, service_name="telnet"),
        ]
        score_res = calc.calculate_asset_score(asset, services=services, findings=[])

        # 3 ports = 4.5 pts
        # ssh (+2.0), redis (+4.0), telnet (+3.0) = 9.0 sensitive pts
        # exposure_base = 4.5 + 9.0 = 13.5
        # multiplier x1.0 (medium), threat x1.0 -> 13.5
        assert score_res.breakdown.exposure_base == 13.5
        assert score_res.score == 13.5
        assert score_res.risk_level == "LOW"

    def test_criticality_weights(self) -> None:
        calc = AttackSurfaceCalculator()
        services = [ServiceRecord(id="s1", asset_id="ast-1", port=80, service_name="http")]
        # 1 port = 1.5 pts + http (3.0 pts) = 4.5 pts

        crit_asset = AssetRecord(id="ast-c", ip_address="10.0.0.1", criticality="critical")
        crit_res = calc.calculate_asset_score(crit_asset, services=services, findings=[])
        assert crit_res.score == pytest.approx(4.5 * 1.5, 0.01)

        low_asset = AssetRecord(id="ast-l", ip_address="10.0.0.2", criticality="low")
        low_res = calc.calculate_asset_score(low_asset, services=services, findings=[])
        assert low_res.score == pytest.approx(4.5 * 0.8, 0.01)

    def test_threat_multiplier_kev_and_rce(self) -> None:
        calc = AttackSurfaceCalculator()
        asset = AssetRecord(id="ast-1", ip_address="10.0.0.1", criticality="medium")
        finding_kev = FindingRecord(
            id="f-kev",
            asset_id="ast-1",
            title="Known Exploited Apache Flaw",
            severity="critical",
            state="confirmed",
            evidence={"is_known_exploited": True},
        )
        score_res = calc.calculate_asset_score(asset, services=[], findings=[finding_kev])

        # critical finding = 25.0 pts
        # is_known_exploited multiplier = 1.35x
        # medium criticality multiplier = 1.0x
        # total = 25.0 * 1.35 = 33.75 -> rounded to 33.8
        assert score_res.breakdown.threat_multiplier == 1.35
        assert score_res.score == pytest.approx(33.8, 0.1)
        assert score_res.top_priority == RiskPriority.P1

    def test_score_clamping_at_100(self) -> None:
        """Massive findings must clamp cleanly at 100.0 max."""
        calc = AttackSurfaceCalculator()
        asset = AssetRecord(id="ast-crit", ip_address="10.0.0.1", criticality="critical")
        services = [
            ServiceRecord(id=f"s{i}", asset_id="ast-crit", port=i, service_name="redis")
            for i in range(1000, 1020)
        ]
        findings = [
            FindingRecord(
                id=f"f{i}",
                asset_id="ast-crit",
                title=f"Critical RCE Vulnerability {i}",
                severity="critical",
                state="confirmed",
                evidence={"is_known_exploited": True, "description": "remote code execution"},
            )
            for i in range(10)
        ]
        score_res = calc.calculate_asset_score(asset, services=services, findings=findings)
        assert score_res.score == 100.0
        assert score_res.risk_level == "CRITICAL"
        assert score_res.top_priority == RiskPriority.P1

    def test_false_positive_finding_ignored(self) -> None:
        """Findings marked as false_positive must not contribute risk points."""
        calc = AttackSurfaceCalculator()
        asset = AssetRecord(id="ast-1", ip_address="10.0.0.1", criticality="medium")
        fp_finding = FindingRecord(
            id="f-fp",
            asset_id="ast-1",
            title="Dismissed Alert",
            severity="critical",
            state="false_positive",
            evidence={},
        )
        score_res = calc.calculate_asset_score(asset, services=[], findings=[fp_finding])
        assert score_res.score == 0.0
        assert score_res.breakdown.findings_subtotal == 0.0


class TestAssessmentRiskPosture:
    """Validate assessment-level posture calculation and repository persistence."""

    def test_assessment_posture_aggregation(self) -> None:
        db_mgr = DatabaseManager("sqlite:///:memory:")
        db_mgr.init_db()
        repo = AssetRepository(db_mgr)

        assessment_id = "test-assessment-100"
        with db_mgr.session() as session:
            session.add(
                AssessmentRecord(
                    id=assessment_id,
                    scope_config={},
                    scanner_version="0.6.0",
                    status="completed",
                )
            )
            # Asset 1: Low risk
            session.add(AssetRecord(id="ast-1", ip_address="192.168.1.10", criticality="low"))
            # Asset 2: High risk
            session.add(AssetRecord(id="ast-2", ip_address="192.168.1.20", criticality="critical"))

            # Service on Asset 1
            session.add(
                ServiceRecord(
                    id="srv-1",
                    asset_id="ast-1",
                    port=80,
                    service_name="http",
                )
            )

            # Service on Asset 2
            session.add(
                ServiceRecord(
                    id="srv-2",
                    asset_id="ast-2",
                    port=6379,
                    service_name="redis",
                )
            )

            # Finding on Asset 2
            session.add(
                FindingRecord(
                    id="fnd-1",
                    assessment_id=assessment_id,
                    asset_id="ast-2",
                    rule_id="RULE-REDIS-NOAUTH",
                    title="Unauthenticated Redis",
                    description="Unauthenticated Redis database exposed.",
                    severity="critical",
                    state="confirmed",
                    evidence={"ip_address": "192.168.1.20", "port": 6379},
                )
            )

        calc = AttackSurfaceCalculator()
        posture = calc.calculate_assessment_posture(assessment_id, repo)

        assert posture.assessment_id == assessment_id
        assert posture.assessed_assets_count == 2
        assert posture.overall_score > 0.0
        assert "P1" in posture.priority_distribution or "P2" in posture.priority_distribution

        # Check repository persistence
        with db_mgr.session() as session:
            rec = session.get(AssessmentRecord, assessment_id)
            assert rec is not None
            assert rec.risk_score == posture.overall_score
            assert rec.risk_posture is not None
            assert rec.risk_posture["overall_score"] == posture.overall_score
