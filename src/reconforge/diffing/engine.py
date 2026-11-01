"""Assessment differencing engine with coverage-aware change detection and risk drift analysis."""

import logging
from datetime import UTC, datetime
from typing import Any

from reconforge.core.enums import RiskPriority
from reconforge.core.scope import parse_ports
from reconforge.diffing.models import (
    AssessmentDiff,
    ChangeCertainty,
    CoverageDelta,
    FindingDelta,
    HostDelta,
    PortDelta,
    RiskDelta,
    RiskDirection,
    ScopeOverlapType,
    ServiceModificationDelta,
)
from reconforge.intelligence.version_matcher import parse_loose_version
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import AssessmentSnapshot, SnapshotManager

logger = logging.getLogger("reconforge.diffing.engine")


class AssessmentDifferencer:
    """Computes explainable, coverage-aware diffs between security assessments or snapshots."""

    def diff_assessments(
        self,
        base_id: str,
        target_id: str,
        repository: AssetRepository,
    ) -> AssessmentDiff:
        """Compare two assessment executions stored in the relational repository."""
        base_ass = repository.get_assessment(base_id)
        if not base_ass:
            # Try prefix lookup
            all_ass = repository.list_assessments(limit=100)
            for a in all_ass:
                if a.id.startswith(base_id):
                    base_ass = a
                    break
        if not base_ass:
            raise ValueError(f"Base assessment '{base_id}' not found.")

        target_ass = repository.get_assessment(target_id)
        if not target_ass:
            all_ass = repository.list_assessments(limit=100)
            for a in all_ass:
                if a.id.startswith(target_id):
                    target_ass = a
                    break
        if not target_ass:
            raise ValueError(f"Target assessment '{target_id}' not found.")

        # Export both to snapshots for unified, deterministic differencing
        snapshot_mgr = SnapshotManager(repository.db)
        base_snap_str = snapshot_mgr.export_snapshot(base_ass.id)
        target_snap_str = snapshot_mgr.export_snapshot(target_ass.id)

        base_snapshot = AssessmentSnapshot.model_validate_json(base_snap_str)
        target_snapshot = AssessmentSnapshot.model_validate_json(target_snap_str)

        return self.diff_snapshots(base_snapshot, target_snapshot)

    def diff_snapshots(
        self,
        base_snapshot: AssessmentSnapshot,
        target_snapshot: AssessmentSnapshot,
    ) -> AssessmentDiff:
        """Compare two standalone assessment snapshots with coverage awareness."""
        # 1. Coverage Delta
        coverage = self._compare_coverage(base_snapshot, target_snapshot)

        # 2. Host Inventory Deltas
        added_hosts, removed_hosts, retained_hosts_count = self._compare_hosts(
            base_snapshot, target_snapshot, coverage
        )

        # 3. Port & Service Deltas
        opened_ports, closed_ports, uncertain_ports, modified_services = (
            self._compare_ports_and_services(base_snapshot, target_snapshot, coverage)
        )

        # 4. Finding & Vulnerability Deltas
        new_findings, resolved_findings, persisting_findings, regressed_findings = (
            self._compare_findings(base_snapshot, target_snapshot, coverage)
        )

        # 5. Risk Posture Delta
        risk = self._compare_risk(base_snapshot, target_snapshot)

        # 6. Synthesize Executive Narrative
        diff = AssessmentDiff(
            base_assessment_id=base_snapshot.assessment.id,
            target_assessment_id=target_snapshot.assessment.id,
            generated_at=datetime.now(UTC),
            coverage=coverage,
            added_hosts=added_hosts,
            removed_hosts=removed_hosts,
            retained_hosts_count=retained_hosts_count,
            opened_ports=opened_ports,
            closed_ports=closed_ports,
            uncertain_ports=uncertain_ports,
            modified_services=modified_services,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persisting_findings=persisting_findings,
            regressed_findings=regressed_findings,
            risk=risk,
        )
        diff.summary_narrative = self.generate_human_summary(diff)
        return diff

    def _compare_coverage(
        self,
        base: AssessmentSnapshot,
        target: AssessmentSnapshot,
    ) -> CoverageDelta:
        """Evaluate scope boundaries, ports, duration, and scanner versions."""
        b_scope = base.assessment.scope_config or {}
        t_scope = target.assessment.scope_config or {}

        b_targets = [str(t).strip() for t in b_scope.get("allowed_targets", []) if str(t).strip()]
        t_targets = [str(t).strip() for t in t_scope.get("allowed_targets", []) if str(t).strip()]

        # Target Sets
        b_target_set = set(b_targets)
        t_target_set = set(t_targets)

        common_targets = sorted(b_target_set & t_target_set)
        unscanned_targets = sorted(b_target_set - t_target_set)
        new_targets = sorted(t_target_set - b_target_set)

        # Port Sets
        b_port_str = b_scope.get("allowed_ports", "1-1024")
        t_port_str = t_scope.get("allowed_ports", "1-1024")

        try:
            b_ports = set(parse_ports(b_port_str))
        except Exception:
            b_ports = set()

        try:
            t_ports = set(parse_ports(t_port_str))
        except Exception:
            t_ports = set()

        common_ports = b_ports & t_ports
        unscanned_ports = b_ports - t_ports
        new_ports = t_ports - b_ports

        # Overlap Classification
        if b_target_set == t_target_set and b_ports == t_ports:
            overlap = ScopeOverlapType.IDENTICAL
        elif b_target_set.issubset(t_target_set) and b_ports.issubset(t_ports):
            overlap = ScopeOverlapType.SUPERSET
        elif t_target_set.issubset(b_target_set) and t_ports.issubset(b_ports):
            overlap = ScopeOverlapType.SUBSET
        elif (b_target_set & t_target_set) and (b_ports & t_ports):
            overlap = ScopeOverlapType.PARTIAL_OVERLAP
        else:
            overlap = ScopeOverlapType.DISJOINT

        is_complete = len(unscanned_targets) == 0 and len(unscanned_ports) == 0

        # Warnings
        warnings: list[str] = []
        if unscanned_ports:
            warnings.append(
                f"Comparison scan omitted {len(unscanned_ports)} ports probed in baseline. "
                "Any absent services on these ports are classified as UNCERTAIN."
            )
        if unscanned_targets:
            warnings.append(
                f"Comparison scan omitted {len(unscanned_targets)} target hosts probed in baseline "
                f"({', '.join(unscanned_targets[:3])}{'...' if len(unscanned_targets) > 3 else ''})."
            )

        ver_change = None
        if base.assessment.scanner_version != target.assessment.scanner_version:
            ver_change = f"ReconForge v{base.assessment.scanner_version} -> v{target.assessment.scanner_version}"

        return CoverageDelta(
            base_scope_config=b_scope,
            target_scope_config=t_scope,
            base_targets=b_targets,
            target_targets=t_targets,
            common_targets=common_targets,
            unscanned_targets=unscanned_targets,
            new_targets=new_targets,
            base_ports_count=len(b_ports),
            target_ports_count=len(t_ports),
            common_ports_count=len(common_ports),
            unscanned_ports_count=len(unscanned_ports),
            new_ports_count=len(new_ports),
            overlap_type=overlap,
            is_coverage_complete=is_complete,
            scanner_version_change=ver_change,
            warnings=warnings,
        )

    def _compare_hosts(
        self,
        base: AssessmentSnapshot,
        target: AssessmentSnapshot,
        coverage: CoverageDelta,
    ) -> tuple[list[HostDelta], list[HostDelta], int]:
        """Detect added, removed, and retained network host assets."""
        b_hosts = {a.ip_address: a for a in base.assets}
        t_hosts = {a.ip_address: a for a in target.assets}

        added: list[HostDelta] = []
        removed: list[HostDelta] = []
        retained_count = 0

        # Newly observed hosts in target
        for ip, asset in t_hosts.items():
            if ip not in b_hosts:
                added.append(
                    HostDelta(
                        ip_address=ip,
                        hostnames=asset.observed_hostnames,
                        criticality=asset.criticality,
                        change_type="added",
                        certainty=ChangeCertainty.DEFINITIVE,
                        reason="Newly discovered active network host",
                    )
                )
            else:
                retained_count += 1

        # Missing hosts that were present in base
        t_target_set = set(coverage.target_targets)
        for ip, asset in b_hosts.items():
            if ip not in t_hosts:
                # Was this host even in target's scan scope?
                if t_target_set and ip not in t_target_set:
                    certainty = ChangeCertainty.UNCERTAIN_SCOPE_MISMATCH
                    reason = "Host omitted from comparison assessment scope"
                else:
                    certainty = ChangeCertainty.DEFINITIVE
                    reason = "Host unobserved or unreachable in comparison assessment"

                removed.append(
                    HostDelta(
                        ip_address=ip,
                        hostnames=asset.observed_hostnames,
                        criticality=asset.criticality,
                        change_type="removed",
                        certainty=certainty,
                        reason=reason,
                    )
                )

        return added, removed, retained_count

    def _compare_ports_and_services(
        self,
        base: AssessmentSnapshot,
        target: AssessmentSnapshot,
        coverage: CoverageDelta,
    ) -> tuple[
        list[PortDelta],
        list[PortDelta],
        list[PortDelta],
        list[ServiceModificationDelta],
    ]:
        """Detect port openings, closures, reachability uncertainties, and service upgrades."""
        b_hosts = {a.ip_address: a for a in base.assets}
        t_hosts = {a.ip_address: a for a in target.assets}

        opened: list[PortDelta] = []
        closed: list[PortDelta] = []
        uncertain: list[PortDelta] = []
        modified: list[ServiceModificationDelta] = []

        # Parse target ports
        try:
            t_port_set = set(
                parse_ports(coverage.target_scope_config.get("allowed_ports", "1-1024"))
            )
        except Exception:
            t_port_set = set()

        try:
            b_port_set = set(parse_ports(coverage.base_scope_config.get("allowed_ports", "1-1024")))
        except Exception:
            b_port_set = set()

        all_ips = sorted(set(b_hosts.keys()) | set(t_hosts.keys()))

        for ip in all_ips:
            b_asset = b_hosts.get(ip)
            t_asset = t_hosts.get(ip)

            b_srvs = {s.port: s for s in (b_asset.services if b_asset else []) if s.port > 0}
            t_srvs = {s.port: s for s in (t_asset.services if t_asset else []) if s.port > 0}

            # Check for opened ports in target
            for port, srv in t_srvs.items():
                if port not in b_srvs:
                    # Was this port scanned in base?
                    if b_port_set and port in b_port_set:
                        certainty = ChangeCertainty.DEFINITIVE
                        reason = "Port transitioned from closed/unresponsive to OPEN"
                    else:
                        certainty = ChangeCertainty.UNCERTAIN_SCOPE_MISMATCH
                        reason = (
                            "Port newly introduced to scan scope; may have been open previously"
                        )

                    opened.append(
                        PortDelta(
                            ip_address=ip,
                            port=port,
                            protocol=srv.protocol,
                            service_name=srv.service_name,
                            product=srv.product,
                            version=srv.version,
                            change_type="opened",
                            certainty=certainty,
                            reason=reason,
                        )
                    )

            # Check for closed or missing ports from base
            for port, srv in b_srvs.items():
                if port not in t_srvs:
                    # Crucial coverage check: was this port even scanned in target?
                    if t_port_set and port not in t_port_set:
                        uncertain.append(
                            PortDelta(
                                ip_address=ip,
                                port=port,
                                protocol=srv.protocol,
                                service_name=srv.service_name,
                                product=srv.product,
                                version=srv.version,
                                change_type="uncertain",
                                certainty=ChangeCertainty.UNCERTAIN_SCOPE_MISMATCH,
                                reason="Port omitted from comparison scan scope; cannot confirm closure",
                            )
                        )
                    elif (
                        ip not in t_hosts
                        and set(coverage.target_targets)
                        and ip not in set(coverage.target_targets)
                    ):
                        uncertain.append(
                            PortDelta(
                                ip_address=ip,
                                port=port,
                                protocol=srv.protocol,
                                service_name=srv.service_name,
                                product=srv.product,
                                version=srv.version,
                                change_type="uncertain",
                                certainty=ChangeCertainty.UNCERTAIN_SCOPE_MISMATCH,
                                reason="Host excluded from comparison scan scope",
                            )
                        )
                    else:
                        closed.append(
                            PortDelta(
                                ip_address=ip,
                                port=port,
                                protocol=srv.protocol,
                                service_name=srv.service_name,
                                product=srv.product,
                                version=srv.version,
                                change_type="closed",
                                certainty=ChangeCertainty.DEFINITIVE,
                                reason="Port verified closed or filtered in comparison assessment",
                            )
                        )

            # Check for modifications on common ports
            common_ports = set(b_srvs.keys()) & set(t_srvs.keys())
            for port in sorted(common_ports):
                b_s = b_srvs[port]
                t_s = t_srvs[port]

                srv_changed = b_s.service_name != t_s.service_name
                prod_changed = b_s.product != t_s.product
                ver_changed = b_s.version != t_s.version
                conf_changed = b_s.confidence != t_s.confidence

                if srv_changed or prod_changed or ver_changed or conf_changed:
                    # Check if version update
                    is_upgrade = False
                    if b_s.version and t_s.version:
                        b_loose = parse_loose_version(b_s.version)
                        t_loose = parse_loose_version(t_s.version)
                        if b_loose and t_loose and t_loose > b_loose:
                            is_upgrade = True

                    notes_list = []
                    if prod_changed:
                        notes_list.append(
                            f"Product: '{b_s.product or '-'}' -> '{t_s.product or '-'}'"
                        )
                    if ver_changed:
                        notes_list.append(
                            f"Version: '{b_s.version or '-'}' -> '{t_s.version or '-'}'"
                        )
                    if srv_changed:
                        notes_list.append(f"Service: '{b_s.service_name}' -> '{t_s.service_name}'")
                    if conf_changed:
                        notes_list.append(f"Confidence: '{b_s.confidence}' -> '{t_s.confidence}'")

                    modified.append(
                        ServiceModificationDelta(
                            ip_address=ip,
                            port=port,
                            protocol=t_s.protocol,
                            old_service_name=b_s.service_name,
                            new_service_name=t_s.service_name,
                            old_product=b_s.product,
                            new_product=t_s.product,
                            old_version=b_s.version,
                            new_version=t_s.version,
                            old_confidence=b_s.confidence,
                            new_confidence=t_s.confidence,
                            is_upgrade=is_upgrade,
                            notes="; ".join(notes_list),
                        )
                    )

        return opened, closed, uncertain, modified

    def _compare_findings(
        self,
        base: AssessmentSnapshot,
        target: AssessmentSnapshot,
        coverage: CoverageDelta,
    ) -> tuple[list[FindingDelta], list[FindingDelta], list[FindingDelta], list[FindingDelta]]:
        """Track finding transitions: new exposures, resolved vulnerabilities, persisting debt, and regressions."""

        # Key: (rule_id, cve_id or '', target_ip, port or 0)
        def finding_key(f: Any) -> tuple[str, str, str, int]:
            return (
                f.rule_id,
                f.cve_id or "",
                f.target_ip,
                f.port or 0,
            )

        b_map = {finding_key(f): f for f in base.findings}
        t_map = {finding_key(f): f for f in target.findings}

        new_f: list[FindingDelta] = []
        resolved_f: list[FindingDelta] = []
        persisting_f: list[FindingDelta] = []
        regressed_f: list[FindingDelta] = []

        try:
            t_port_set = set(
                parse_ports(coverage.target_scope_config.get("allowed_ports", "1-1024"))
            )
        except Exception:
            t_port_set = set()

        t_targets_set = set(coverage.target_targets)

        # 1. New findings in target
        for k, f in t_map.items():
            if k not in b_map:
                new_f.append(
                    FindingDelta(
                        finding_id=f.id,
                        rule_id=f.rule_id,
                        cve_id=f.cve_id,
                        title=f.title,
                        severity=f.severity,
                        priority=f.priority,
                        target_ip=f.target_ip,
                        port=f.port,
                        change_type="new",
                        certainty=ChangeCertainty.DEFINITIVE,
                    )
                )

        # 2. Base findings evaluation
        for k, f in b_map.items():
            if k in t_map:
                t_finding = t_map[k]
                # Check for regression (previously accepted or false positive that reappeared as confirmed)
                if f.state.lower() in {
                    "accepted_risk",
                    "false_positive",
                } and t_finding.state.lower() in {
                    "confirmed",
                    "potential_vulnerability",
                    "potential_exposure",
                }:
                    regressed_f.append(
                        FindingDelta(
                            finding_id=t_finding.id,
                            rule_id=f.rule_id,
                            cve_id=f.cve_id,
                            title=f.title,
                            severity=t_finding.severity,
                            priority=t_finding.priority,
                            target_ip=f.target_ip,
                            port=f.port,
                            change_type="regressed",
                            certainty=ChangeCertainty.DEFINITIVE,
                            resolution_reason=f"Previously '{f.state}' finding reactivated as '{t_finding.state}'",
                        )
                    )
                else:
                    persisting_f.append(
                        FindingDelta(
                            finding_id=t_finding.id,
                            rule_id=f.rule_id,
                            cve_id=f.cve_id,
                            title=f.title,
                            severity=t_finding.severity,
                            priority=t_finding.priority,
                            target_ip=f.target_ip,
                            port=f.port,
                            change_type="persisting",
                            certainty=ChangeCertainty.DEFINITIVE,
                        )
                    )
            else:
                # Finding no longer observed in target
                # Check coverage: was the target IP and port scanned?
                is_ip_covered = not t_targets_set or f.target_ip in t_targets_set
                is_port_covered = not f.port or (t_port_set and f.port in t_port_set)

                if is_ip_covered and is_port_covered:
                    certainty = ChangeCertainty.DEFINITIVE
                    reason = "Condition remediated (port closed, service updated, or exposure eliminated)"
                else:
                    certainty = ChangeCertainty.UNCERTAIN_SCOPE_MISMATCH
                    reason = "Associated host or port was omitted from comparison scan; resolution unverified"

                resolved_f.append(
                    FindingDelta(
                        finding_id=f.id,
                        rule_id=f.rule_id,
                        cve_id=f.cve_id,
                        title=f.title,
                        severity=f.severity,
                        priority=f.priority,
                        target_ip=f.target_ip,
                        port=f.port,
                        change_type="resolved",
                        certainty=certainty,
                        resolution_reason=reason,
                    )
                )

        return new_f, resolved_f, persisting_f, regressed_f

    def _compare_risk(
        self,
        base: AssessmentSnapshot,
        target: AssessmentSnapshot,
    ) -> RiskDelta:
        """Calculate numerical risk score variance and priority tier fluctuations."""
        b_score = base.assessment.risk_score or 0.0
        t_score = target.assessment.risk_score or 0.0

        if b_score == 0.0 and base.risk_posture and "overall_score" in base.risk_posture:
            b_score = float(base.risk_posture["overall_score"])

        if t_score == 0.0 and target.risk_posture and "overall_score" in target.risk_posture:
            t_score = float(target.risk_posture["overall_score"])

        delta = round(t_score - b_score, 1)

        if delta <= -1.0:
            direction = RiskDirection.IMPROVED
        elif delta >= 1.0:
            direction = RiskDirection.DEGRADED
        else:
            direction = RiskDirection.STABLE

        # Risk level string
        def score_to_level(score: float) -> str:
            if score >= 80.0:
                return "CRITICAL"
            elif score >= 60.0:
                return "HIGH"
            elif score >= 35.0:
                return "MEDIUM"
            elif score >= 10.0:
                return "LOW"
            return "NEGLIGIBLE"

        b_level = (base.risk_posture or {}).get("risk_level") or score_to_level(b_score)
        t_level = (target.risk_posture or {}).get("risk_level") or score_to_level(t_score)

        # Priority count changes
        b_p_dist = (
            (base.risk_posture or {}).get("priority_distribution")
            or (base.risk_posture or {}).get("priority_breakdown")
            or {}
        )
        t_p_dist = (
            (target.risk_posture or {}).get("priority_distribution")
            or (target.risk_posture or {}).get("priority_breakdown")
            or {}
        )

        # If priority distributions are missing, compute from findings
        if not b_p_dist and base.findings:
            b_p_dist = {p.value: 0 for p in RiskPriority}
            for f in base.findings:
                b_p_dist[f.priority.upper()] = b_p_dist.get(f.priority.upper(), 0) + 1

        if not t_p_dist and target.findings:
            t_p_dist = {p.value: 0 for p in RiskPriority}
            for f in target.findings:
                t_p_dist[f.priority.upper()] = t_p_dist.get(f.priority.upper(), 0) + 1

        priority_changes: dict[str, int] = {}
        for p in ["P1", "P2", "P3", "P4", "P5"]:
            b_c = b_p_dist.get(p, 0)
            t_c = t_p_dist.get(p, 0)
            priority_changes[p] = t_c - b_c

        return RiskDelta(
            base_score=b_score,
            target_score=t_score,
            score_delta=delta,
            base_risk_level=b_level,
            target_risk_level=t_level,
            direction=direction,
            priority_changes=priority_changes,
        )

    def generate_human_summary(self, diff: AssessmentDiff) -> list[str]:
        """Synthesize high-level plain-English narrative summarizing attack-surface evolution."""
        bullets: list[str] = []

        # 1. Posture & Risk Movement
        risk = diff.risk
        direction_badge = {
            RiskDirection.IMPROVED: "🟢 IMPROVED",
            RiskDirection.DEGRADED: "🔴 DEGRADED",
            RiskDirection.STABLE: "⚪ STABLE",
        }.get(risk.direction, "STABLE")

        delta_sign = (
            f"+{risk.score_delta:.1f}" if risk.score_delta > 0 else f"{risk.score_delta:.1f}"
        )
        bullets.append(
            f"Overall Attack-Surface Risk: {direction_badge} ({delta_sign} pts shift, "
            f"from {risk.base_score:.1f} [{risk.base_risk_level}] to {risk.target_score:.1f} [{risk.target_risk_level}])."
        )

        # 2. Coverage Summary
        cov = diff.coverage
        if cov.overlap_type == ScopeOverlapType.IDENTICAL:
            bullets.append(
                f"Scan Coverage: Identical scope boundaries ({cov.common_ports_count} ports across {len(cov.common_targets)} target hosts)."
            )
        else:
            bullets.append(
                f"Scan Coverage: {cov.overlap_type.value.upper()} overlap. "
                f"Common ports: {cov.common_ports_count}, Unscanned ports: {cov.unscanned_ports_count}, New ports: {cov.new_ports_count}."
            )

        # 3. Host Transitions
        if diff.added_hosts:
            added_ips = ", ".join(h.ip_address for h in diff.added_hosts[:4])
            bullets.append(
                f"Host Inventory: {len(diff.added_hosts)} new host(s) discovered ({added_ips})."
            )
        if diff.removed_hosts:
            rem_ips = ", ".join(h.ip_address for h in diff.removed_hosts[:4])
            bullets.append(
                f"Host Inventory: {len(diff.removed_hosts)} host(s) unobserved or decommissioned ({rem_ips})."
            )

        # 4. Port & Service Transitions
        if diff.opened_ports:
            opened_desc = ", ".join(f"{p.ip_address}:{p.port}" for p in diff.opened_ports[:4])
            bullets.append(
                f"Network Perimeter: ⚠️ {len(diff.opened_ports)} newly opened transport port(s) ({opened_desc})."
            )

        if diff.closed_ports:
            closed_desc = ", ".join(f"{p.ip_address}:{p.port}" for p in diff.closed_ports[:4])
            bullets.append(
                f"Network Perimeter: 🛡️ {len(diff.closed_ports)} port(s) confirmed closed or filtered ({closed_desc})."
            )

        if diff.uncertain_ports:
            bullets.append(
                f"Network Perimeter: ❓ {len(diff.uncertain_ports)} port(s) unassessed in comparison scan (uncertain closure)."
            )

        # 5. Service Upgrades & Modifications
        upgrades = [m for m in diff.modified_services if m.is_upgrade]
        if upgrades:
            up_desc = ", ".join(
                f"{m.ip_address}:{m.port} ({m.old_version} -> {m.new_version})"
                for m in upgrades[:3]
            )
            bullets.append(
                f"Software Hygiene: 🚀 {len(upgrades)} verified software version upgrade(s) ({up_desc})."
            )

        other_mods = [m for m in diff.modified_services if not m.is_upgrade]
        if other_mods:
            bullets.append(
                f"Service Configuration: {len(other_mods)} service identification/banner change(s) detected."
            )

        # 6. Vulnerabilities & Findings
        if diff.new_findings:
            p1_count = sum(1 for f in diff.new_findings if f.priority == "P1")
            p2_count = sum(1 for f in diff.new_findings if f.priority == "P2")
            bullets.append(
                f"Security Exposures: 🚨 {len(diff.new_findings)} new security finding(s) detected "
                f"({p1_count} P1 Critical, {p2_count} P2 High)."
            )

        if diff.resolved_findings:
            bullets.append(
                f"Remediation Tracking: ✅ {len(diff.resolved_findings)} previously detected finding(s) successfully resolved."
            )

        if diff.regressed_findings:
            bullets.append(
                f"Security Regression: ⚠️ {len(diff.regressed_findings)} finding(s) previously marked accepted/resolved have regressed."
            )

        if diff.persisting_findings:
            bullets.append(
                f"Outstanding Technical Debt: {len(diff.persisting_findings)} finding(s) remain unremediated."
            )

        return bullets
