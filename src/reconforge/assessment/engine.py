"""Exposure assessment evaluation engine."""

import logging
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from reconforge.assessment.builtin_rules import BUILTIN_RULES
from reconforge.assessment.custom_rules import load_rules_from_directory, load_rules_from_file
from reconforge.assessment.models import ExposureRuleDefinition, Finding, RuleCondition
from reconforge.core.enums import (
    FindingCategory,
    ObservationConfidence,
    SeverityLevel,
)
from reconforge.core.models import PortObservation
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, FindingRecord

logger = logging.getLogger("reconforge.assessment.engine")


class ExposureEngine:
    """Evaluates declarative exposure rules against discovered network assets and services."""

    def __init__(self, include_builtin: bool = True):
        self._rules: dict[str, ExposureRuleDefinition] = {}
        if include_builtin:
            for rule in BUILTIN_RULES:
                self.register_rule(rule)

    def register_rule(self, rule: ExposureRuleDefinition) -> None:
        """Register or overwrite an exposure rule in the active rulebook."""
        self._rules[rule.id] = rule

    def load_custom_file(self, path: str) -> list[ExposureRuleDefinition]:
        """Load and register custom rules from a YAML file."""
        rules = load_rules_from_file(path)
        for rule in rules:
            self.register_rule(rule)
        return rules

    def load_custom_directory(self, path: str) -> tuple[list[ExposureRuleDefinition], list[str]]:
        """Load and register all custom rules from a directory."""
        rules, errors = load_rules_from_directory(path)
        for rule in rules:
            self.register_rule(rule)
        return rules, errors

    def get_rule(self, rule_id: str) -> ExposureRuleDefinition | None:
        """Retrieve a registered rule by its identifier."""
        return self._rules.get(rule_id)

    def list_rules(
        self,
        category: FindingCategory | str | None = None,
        severity: SeverityLevel | str | None = None,
        enabled_only: bool = True,
    ) -> list[ExposureRuleDefinition]:
        """List registered exposure rules matching optional filter criteria."""
        result: list[ExposureRuleDefinition] = []
        for rule in self._rules.values():
            if enabled_only and not rule.enabled:
                continue
            if category and rule.category != category:
                continue
            if severity and rule.severity != severity:
                continue
            result.append(rule)
        return sorted(result, key=lambda r: r.id)

    def evaluate_service(
        self,
        rule: ExposureRuleDefinition,
        port: int,
        protocol: str,
        service_name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        banner_snippet: str | None = None,
        tls_metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, list[str]]:
        """Evaluate a single rule against service attributes.

        Returns:
            (is_matched, list_of_matched_reasons)
        """
        cond: RuleCondition = rule.conditions
        matches: list[str] = []
        checks_total = 0

        # 0. Transport Protocol Prerequisite Check
        if cond.protocols and protocol.lower() not in [p.lower() for p in cond.protocols]:
            return False, []

        # 1. Port Check
        if cond.ports:
            checks_total += 1
            if port in cond.ports:
                matches.append(f"port={port}")
            elif cond.require_all:
                return False, []

        # 2. Service Name Check
        if cond.service_names:
            checks_total += 1
            cur_svc = (service_name or "").lower()
            if any(s.lower() == cur_svc or s.lower() in cur_svc for s in cond.service_names):
                matches.append(f"service_name={service_name}")
            elif cond.require_all:
                return False, []

        # 3. Product Check
        if cond.products:
            checks_total += 1
            cur_prod = (product or "").lower()
            if any(p.lower() == cur_prod or p.lower() in cur_prod for p in cond.products):
                matches.append(f"product={product}")
            elif cond.require_all:
                return False, []

        # 4. Version Pattern Check
        if cond.version_pattern:
            checks_total += 1
            cur_ver = version or ""
            if cur_ver and re.search(cond.version_pattern, cur_ver):
                matches.append(f"version_regex_match='{cond.version_pattern}' on '{cur_ver}'")
            elif cond.require_all:
                return False, []

        # 5. Banner Pattern Check
        if cond.banner_pattern:
            checks_total += 1
            cur_ban = banner_snippet or ""
            if cur_ban and re.search(cond.banner_pattern, cur_ban):
                matches.append(f"banner_regex_match='{cond.banner_pattern}'")
            elif cond.require_all:
                return False, []

        # 6. TLS Conditions Check
        if cond.tls_conditions:
            checks_total += 1
            tls = tls_metadata or {}
            tls_matched = False

            if cond.tls_conditions.get("expired") is True and tls.get("is_expired") is True:
                matches.append("tls_certificate_expired")
                tls_matched = True

            if cond.tls_conditions.get("self_signed") is True and tls.get("is_self_signed") is True:
                matches.append("tls_certificate_self_signed")
                tls_matched = True

            disallowed = cond.tls_conditions.get("disallowed_protocols", [])
            proto = tls.get("protocol_version")
            if disallowed and proto and proto in disallowed:
                matches.append(f"tls_disallowed_protocol={proto}")
                tls_matched = True

            if not tls_matched and cond.require_all:
                return False, []

        # Final decision based on require_all flag
        if checks_total == 0:
            return False, []

        if cond.require_all:
            return len(matches) == checks_total, matches
        else:
            return len(matches) > 0, matches

    def evaluate_observations(
        self,
        assessment_id: str,
        asset_id: str,
        observations: list[PortObservation],
    ) -> list[Finding]:
        """Evaluate registered exposure rules directly against live scan PortObservations."""
        findings: list[Finding] = []
        for obs in observations:
            if obs.state != "open":
                continue

            srv = obs.service
            service_name = srv.service_name if srv else None
            product = srv.product if srv else None
            version = srv.version if srv else None
            banner = srv.banner_snippet if srv else None
            tls_meta = srv.tls_info.model_dump(mode="json") if (srv and srv.tls_info) else None
            confidence = srv.confidence if srv else ObservationConfidence.UNKNOWN

            for rule in self.list_rules(enabled_only=True):
                matched, reasons = self.evaluate_service(
                    rule=rule,
                    port=obs.port,
                    protocol=obs.protocol,
                    service_name=service_name,
                    product=product,
                    version=version,
                    banner_snippet=banner,
                    tls_metadata=tls_meta,
                )
                if matched:
                    evidence = {
                        "matched_rule_id": rule.id,
                        "port": obs.port,
                        "protocol": obs.protocol,
                        "service_name": service_name,
                        "product": product,
                        "version": version,
                        "banner_snippet": banner,
                        "matched_criteria": reasons,
                        "tls_metadata": tls_meta,
                        "response_time_ms": obs.response_time_ms,
                    }
                    findings.append(
                        Finding(
                            assessment_id=assessment_id,
                            asset_id=asset_id,
                            service_id=None,
                            rule_id=rule.id,
                            title=rule.name,
                            description=rule.description,
                            severity=rule.severity,
                            state=rule.default_state,
                            confidence=confidence,
                            evidence=evidence,
                            remediation_guidance=rule.remediation,
                        )
                    )
        return findings

    def evaluate_assessment(
        self,
        assessment_id: str,
        db_manager: DatabaseManager,
        persist: bool = True,
    ) -> list[Finding]:
        """Evaluate registered exposure rules against all assets and services in an assessment.

        Optionally persists findings to the relational database with deduplication.
        """
        produced_findings: list[Finding] = []

        with db_manager.session() as session:
            # Query assessment by UUID or prefix
            stmt = (
                select(AssessmentRecord)
                .options(selectinload(AssessmentRecord.findings))
                .where(
                    (AssessmentRecord.id == assessment_id)
                    | (AssessmentRecord.id.startswith(assessment_id))
                )
            )
            assessment = session.execute(stmt).scalars().first()
            if not assessment:
                logger.warning("Assessment '%s' not found for exposure evaluation.", assessment_id)
                return []

            # Retrieve all assets associated with the inventory
            asset_stmt = select(AssetRecord).options(selectinload(AssetRecord.services))
            assets = session.execute(asset_stmt).scalars().all()

            for asset in assets:
                for service in asset.services:
                    for rule in self.list_rules(enabled_only=True):
                        matched, reasons = self.evaluate_service(
                            rule=rule,
                            port=service.port,
                            protocol=service.protocol,
                            service_name=service.service_name,
                            product=service.product,
                            version=service.version,
                            banner_snippet=service.banner_snippet,
                            tls_metadata=service.tls_metadata,
                        )
                        if matched:
                            evidence = {
                                "matched_rule_id": rule.id,
                                "ip_address": asset.ip_address,
                                "port": service.port,
                                "protocol": service.protocol,
                                "service_name": service.service_name,
                                "product": service.product,
                                "version": service.version,
                                "banner_snippet": service.banner_snippet,
                                "matched_criteria": reasons,
                                "tls_metadata": service.tls_metadata,
                            }
                            finding_model = Finding(
                                assessment_id=assessment.id,
                                asset_id=asset.id,
                                service_id=service.id,
                                rule_id=rule.id,
                                title=rule.name,
                                description=rule.description,
                                severity=rule.severity,
                                state=rule.default_state,
                                confidence=ObservationConfidence(service.confidence)
                                if service.confidence in ObservationConfidence
                                else ObservationConfidence.MEDIUM,
                                evidence=evidence,
                                remediation_guidance=rule.remediation,
                            )
                            produced_findings.append(finding_model)

                            if persist:
                                # Deduplication check on (assessment_id, asset_id, service_id, rule_id)
                                existing_finding = session.execute(
                                    select(FindingRecord).where(
                                        FindingRecord.assessment_id == assessment.id,
                                        FindingRecord.asset_id == asset.id,
                                        FindingRecord.service_id == service.id,
                                        FindingRecord.rule_id == rule.id,
                                    )
                                ).scalar_one_or_none()

                                if not existing_finding:
                                    record = FindingRecord(
                                        id=finding_model.id,
                                        assessment_id=finding_model.assessment_id,
                                        asset_id=finding_model.asset_id,
                                        service_id=finding_model.service_id,
                                        rule_id=finding_model.rule_id,
                                        cve_id=finding_model.cve_id,
                                        title=finding_model.title,
                                        description=finding_model.description,
                                        severity=finding_model.severity.value,
                                        state=finding_model.state.value,
                                        evidence=finding_model.evidence,
                                        remediation_guidance=finding_model.remediation_guidance,
                                    )
                                    session.add(record)
                                else:
                                    # Update evidence and timestamp if already recorded
                                    existing_finding.evidence = finding_model.evidence
                                    existing_finding.updated_at = datetime.now(UTC)

        return produced_findings
