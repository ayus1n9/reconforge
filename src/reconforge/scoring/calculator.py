"""Mathematical attack-surface scoring algorithm and deterministic risk prioritization engine."""

import logging

from reconforge.core.enums import (
    AssetCriticality,
    FindingCategory,
    FindingState,
    RiskPriority,
    SeverityLevel,
)
from reconforge.inventory.repository import AssetRepository
from reconforge.scoring.models import (
    AssessmentRiskPosture,
    AssetRiskScore,
    ScoreBreakdown,
)
from reconforge.storage.models import AssessmentRecord, AssetRecord, FindingRecord, ServiceRecord

logger = logging.getLogger("reconforge.scoring.calculator")

# Criticality multiplier factors
CRITICALITY_WEIGHTS: dict[AssetCriticality, float] = {
    AssetCriticality.CRITICAL: 1.5,
    AssetCriticality.HIGH: 1.2,
    AssetCriticality.MEDIUM: 1.0,
    AssetCriticality.LOW: 0.8,
}

# Finding severity baseline point values
SEVERITY_WEIGHTS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 25.0,
    SeverityLevel.HIGH: 15.0,
    SeverityLevel.MEDIUM: 7.0,
    SeverityLevel.LOW: 2.0,
    SeverityLevel.INFORMATIONAL: 0.5,
}

# Finding state evaluation weights
STATE_MODIFIERS: dict[str, float] = {
    FindingState.CONFIRMED.value: 1.0,
    FindingState.POTENTIAL_VULNERABILITY.value: 0.9,
    FindingState.POTENTIAL_EXPOSURE.value: 0.75,
    FindingState.NEEDS_REVIEW.value: 0.6,
    FindingState.INFORMATIONAL.value: 0.3,
    FindingState.ACCEPTED_RISK.value: 0.1,
    FindingState.FALSE_POSITIVE.value: 0.0,
}

# Known sensitive service protocols
CLEARTEXT_SERVICES = {"telnet", "ftp", "http"}
DATABASE_SERVICES = {"redis", "mysql", "postgresql", "postgres", "mongodb", "elasticsearch"}
MANAGEMENT_SERVICES = {"ssh", "rdp", "vnc", "docker", "kubernetes"}


class AttackSurfaceCalculator:
    """Computes defensible attack-surface risk scores and deterministic remediation priorities."""

    @classmethod
    def get_finding_priority(
        cls,
        severity: SeverityLevel | str,
        asset_criticality: AssetCriticality = AssetCriticality.MEDIUM,
        is_known_exploited: bool = False,
        category: FindingCategory | str | None = None,
    ) -> RiskPriority:
        """Determine remediation urgency (P1 to P5) based on severity, exploitability, and asset tier."""
        sev = (
            severity
            if isinstance(severity, SeverityLevel)
            else SeverityLevel(str(severity).lower())
        )

        # P1: Actively exploited (CISA KEV) or Critical vulnerability on High/Critical asset
        if is_known_exploited:
            return RiskPriority.P1
        if sev == SeverityLevel.CRITICAL and asset_criticality in {
            AssetCriticality.CRITICAL,
            AssetCriticality.HIGH,
        }:
            return RiskPriority.P1

        # P2: Critical on Medium/Low asset, or High severity vulnerability/exposure, or Database exposure
        if sev == SeverityLevel.CRITICAL:
            return RiskPriority.P2
        if sev == SeverityLevel.HIGH:
            return RiskPriority.P2
        if category and str(category).lower() == FindingCategory.DATABASE_EXPOSURE.value:
            return RiskPriority.P2

        # P3: Medium severity exposure (cleartext, TLS misconfiguration, etc.)
        if sev == SeverityLevel.MEDIUM:
            return RiskPriority.P3

        # P4: Low severity exposure or minor configuration issue
        if sev == SeverityLevel.LOW:
            return RiskPriority.P4

        # P5: Informational observations or routine hygiene
        return RiskPriority.P5

    @classmethod
    def score_to_risk_level(cls, score: float) -> str:
        """Map numerical score to standard risk rating."""
        if score >= 80.0:
            return "CRITICAL"
        elif score >= 60.0:
            return "HIGH"
        elif score >= 35.0:
            return "MEDIUM"
        elif score >= 10.0:
            return "LOW"
        return "NEGLIGIBLE"

    def calculate_asset_score(
        self,
        asset: AssetRecord,
        services: list[ServiceRecord],
        findings: list[FindingRecord],
    ) -> AssetRiskScore:
        """Calculate attack-surface risk score for a single asset with full mathematical breakdown."""
        explanations: list[str] = []

        # 1. Asset Criticality Weight
        try:
            crit_enum = AssetCriticality(asset.criticality.lower())
        except (ValueError, AttributeError):
            crit_enum = AssetCriticality.MEDIUM

        crit_weight = CRITICALITY_WEIGHTS.get(crit_enum, 1.0)
        explanations.append(
            f"Asset Criticality [{crit_enum.value.upper()}]: multiplier x{crit_weight:.2f}"
        )

        # 2. Network Exposure Base
        open_services = [s for s in services if s.port > 0]
        port_count = len(open_services)
        port_points = min(15.0, port_count * 1.5)
        sensitive_points = 0.0

        for s in open_services:
            name = (s.service_name or "").lower()
            if name in DATABASE_SERVICES:
                sensitive_points += 4.0
                explanations.append(
                    f"Exposed Database Service: {name}:{s.port} (+4.0 exposure points)"
                )
            elif name in CLEARTEXT_SERVICES:
                sensitive_points += 3.0
                explanations.append(
                    f"Exposed Cleartext Service: {name}:{s.port} (+3.0 exposure points)"
                )
            elif name in MANAGEMENT_SERVICES:
                sensitive_points += 2.0
                explanations.append(
                    f"Exposed Management Service: {name}:{s.port} (+2.0 exposure points)"
                )

        exposure_base = min(25.0, port_points + sensitive_points)
        explanations.append(
            f"Network Exposure Subtotal: {exposure_base:.1f} pts ({port_count} ports: {port_points:.1f} pts, sensitive services: {sensitive_points:.1f} pts)"
        )

        # 3. Security Findings Subtotal
        findings_subtotal = 0.0
        has_cisa_kev = False
        has_critical_rce = False
        priorities: list[RiskPriority] = []

        for f in findings:
            state_mod = STATE_MODIFIERS.get(f.state.lower(), 1.0)
            if state_mod == 0.0:
                continue  # False positive ignored

            try:
                sev_enum = SeverityLevel(f.severity.lower())
            except ValueError:
                sev_enum = SeverityLevel.MEDIUM

            base_pts = SEVERITY_WEIGHTS.get(sev_enum, 7.0)
            weighted_pts = base_pts * state_mod
            findings_subtotal += weighted_pts

            # Inspect threat intelligence evidence
            evidence = f.evidence or {}
            is_kev = bool(evidence.get("is_known_exploited"))
            if is_kev:
                has_cisa_kev = True

            cvss = evidence.get("cvss_v3_score")
            if cvss and float(cvss) >= 9.0:
                has_critical_rce = True

            # Assign priority
            pri = self.get_finding_priority(
                severity=sev_enum,
                asset_criticality=crit_enum,
                is_known_exploited=is_kev,
                category=f.rule_id,
            )
            priorities.append(pri)

        explanations.append(
            f"Findings Severity Subtotal: {findings_subtotal:.1f} pts across {len(priorities)} active findings"
        )

        # 4. Threat Multiplier
        threat_multiplier = 1.0
        if has_cisa_kev:
            threat_multiplier = 1.35
            explanations.append(
                "Threat Intelligence Modifier: CISA KEV Exploitation listed (+35% multiplier x1.35)"
            )
        elif has_critical_rce:
            threat_multiplier = 1.15
            explanations.append(
                "Threat Intelligence Modifier: Critical CVSS 9.0+ RCE potential (+15% multiplier x1.15)"
            )

        # 5. Composite Calculation
        raw_score = (exposure_base + findings_subtotal) * crit_weight * threat_multiplier
        final_score = min(100.0, max(0.0, round(raw_score, 1)))

        top_priority = RiskPriority.P5
        for target_p in [
            RiskPriority.P1,
            RiskPriority.P2,
            RiskPriority.P3,
            RiskPriority.P4,
            RiskPriority.P5,
        ]:
            if target_p in priorities:
                top_priority = target_p
                break

        risk_level = self.score_to_risk_level(final_score)

        breakdown = ScoreBreakdown(
            exposure_base=round(exposure_base, 1),
            findings_subtotal=round(findings_subtotal, 1),
            criticality_factor=crit_weight,
            threat_multiplier=threat_multiplier,
            raw_score=round(raw_score, 1),
            final_score=final_score,
            component_explanations=explanations,
        )

        return AssetRiskScore(
            asset_id=asset.id,
            ip_address=asset.ip_address,
            criticality=crit_enum,
            score=final_score,
            risk_level=risk_level,
            top_priority=top_priority,
            breakdown=breakdown,
            active_findings_count=len(priorities),
            open_services_count=port_count,
        )

    def calculate_assessment_posture(
        self,
        assessment_id: str,
        repository: AssetRepository,
    ) -> AssessmentRiskPosture:
        """Calculate aggregate posture score, distributions, and top drivers for an assessment run."""
        asset_scores: list[AssetRiskScore] = []
        priority_dist = {p.value: 0 for p in RiskPriority}
        severity_dist = {s.value: 0 for s in SeverityLevel}
        drivers: list[str] = []

        with repository.db.session() as session:
            # 1. Fetch assessment
            assessment = session.get(AssessmentRecord, assessment_id)
            if not assessment:
                # Try prefix lookup
                all_ass = repository.list_assessments(limit=100)
                for a in all_ass:
                    if a.id.startswith(assessment_id):
                        assessment = session.get(AssessmentRecord, a.id)
                        break

            if not assessment:
                raise ValueError(f"Assessment '{assessment_id}' not found.")

            # 2. Fetch all findings and assets
            findings = repository.list_findings(assessment_id=assessment.id)
            assets = repository.list_assets(limit=500)

            # Group findings by asset_id
            findings_by_asset: dict[str, list[FindingRecord]] = {}
            for f in findings:
                findings_by_asset.setdefault(f.asset_id, []).append(f)
                # Count distributions
                sev_key = f.severity.lower()
                if sev_key in severity_dist:
                    severity_dist[sev_key] += 1

                pri_val = f.priority.upper() if f.priority else "P4"
                if pri_val in priority_dist:
                    priority_dist[pri_val] += 1

                # Collect high-impact drivers
                if f.severity.lower() in {"critical", "high"}:
                    driver_text = f"{f.title} ({f.rule_id})"
                    if driver_text not in drivers and len(drivers) < 8:
                        drivers.append(driver_text)

            # 3. Calculate scores for each asset
            for asset in assets:
                services = list(asset.services or [])
                asset_findings = findings_by_asset.get(asset.id, [])
                if not services and not asset_findings:
                    continue

                score_obj = self.calculate_asset_score(asset, services, asset_findings)
                asset_scores.append(score_obj)

                # Persist score back to AssetRecord
                asset.risk_score = score_obj.score
                asset.risk_breakdown = score_obj.breakdown.model_dump()

            session.commit()

        # 4. Compute composite posture score
        if not asset_scores:
            overall_score = 0.0
        else:
            scores_list = [a.score for a in asset_scores]
            max_score = max(scores_list)
            avg_score = sum(scores_list) / len(scores_list)
            # Max-anchored formula (60% weight on worst-case asset, 40% on average estate health)
            overall_score = min(100.0, max(0.0, round(0.6 * max_score + 0.4 * avg_score, 1)))

        risk_level = self.score_to_risk_level(overall_score)
        assets_at_risk = sum(1 for a in asset_scores if a.score > 0.0)

        # Persist aggregate score back to AssessmentRecord
        with repository.db.session() as session:
            ass_rec = session.get(AssessmentRecord, assessment.id)
            if ass_rec:
                ass_rec.risk_score = overall_score
                ass_rec.risk_posture = {
                    "overall_score": overall_score,
                    "risk_level": risk_level,
                    "assets_at_risk": assets_at_risk,
                    "priority_distribution": priority_dist,
                    "severity_distribution": severity_dist,
                }
                session.commit()

        return AssessmentRiskPosture(
            assessment_id=assessment.id,
            overall_score=overall_score,
            risk_level=risk_level,
            assessed_assets_count=len(asset_scores),
            assets_at_risk_count=assets_at_risk,
            priority_distribution=priority_dist,
            severity_distribution=severity_dist,
            asset_scores=sorted(asset_scores, key=lambda a: a.score, reverse=True),
            key_exposure_drivers=drivers,
            metadata={"scanner_version": assessment.scanner_version},
        )
