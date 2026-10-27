"""Unit tests for custom YAML rule loading, schema validation, and error reporting."""

import tempfile
from pathlib import Path

import pytest

from reconforge.assessment.custom_rules import (
    RuleLoadingError,
    load_rules_from_file,
)
from reconforge.assessment.engine import ExposureEngine
from reconforge.core.enums import FindingCategory, SeverityLevel


def test_load_valid_single_rule():
    yaml_content = """
id: EXP-CUSTOM-GRAPHQL
name: Exposed GraphQL Introspection Endpoint
description: GraphQL service detected with introspection queries potentially enabled.
severity: medium
category: insecure_management
default_state: potential_exposure
conditions:
  ports: [4000, 8000]
  service_names: ["http"]
  banner_pattern: "(?i)graphql"
  require_all: false
remediation: Disable GraphQL schema introspection in production environments.
references:
  - "OWASP API Security Top 10: API7:2023 Security Misconfiguration"
tags: ["api", "graphql"]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(yaml_content)
        tmp_path = tmp.name

    try:
        rules = load_rules_from_file(tmp_path)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.id == "EXP-CUSTOM-GRAPHQL"
        assert rule.severity == SeverityLevel.MEDIUM
        assert rule.category == FindingCategory.INSECURE_MANAGEMENT
        assert 4000 in rule.conditions.ports
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_load_multi_rule_list():
    yaml_content = """
- id: EXP-CUSTOM-RULE-A
  name: Custom Rule A
  description: Rule A description.
  severity: low
  category: network_exposure
  conditions:
    ports: [9000]
  remediation: Fix rule A.
- id: EXP-CUSTOM-RULE-B
  name: Custom Rule B
  description: Rule B description.
  severity: critical
  category: insecure_management
  conditions:
    ports: [9001]
  remediation: Fix rule B.
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(yaml_content)
        tmp_path = tmp.name

    try:
        rules = load_rules_from_file(tmp_path)
        assert len(rules) == 2
        assert rules[0].id == "EXP-CUSTOM-RULE-A"
        assert rules[1].id == "EXP-CUSTOM-RULE-B"
        assert rules[1].severity == SeverityLevel.CRITICAL
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_load_rules_from_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        dir_path = Path(tmpdir)
        (dir_path / "rule1.yaml").write_text(
            """
id: EXP-DIR-RULE-1
name: Directory Rule 1
description: Test rule 1.
severity: high
category: database_exposure
conditions:
  ports: [1521]
remediation: Oracle DB guidance.
""",
            encoding="utf-8",
        )

        (dir_path / "rule2.yml").write_text(
            """
id: EXP-DIR-RULE-2
name: Directory Rule 2
description: Test rule 2.
severity: medium
category: information_disclosure
conditions:
  banner_pattern: "internal-host"
remediation: Suppress header.
""",
            encoding="utf-8",
        )

        engine = ExposureEngine(include_builtin=False)
        rules, errors = engine.load_custom_directory(str(dir_path))
        assert len(rules) == 2
        assert len(errors) == 0
        assert engine.get_rule("EXP-DIR-RULE-1") is not None
        assert engine.get_rule("EXP-DIR-RULE-2") is not None


def test_reject_invalid_port_range():
    yaml_content = """
id: EXP-INVALID-PORT
name: Invalid Port Test
description: Out of bounds port test.
severity: high
category: network_exposure
conditions:
  ports: [99999]
remediation: None.
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(yaml_content)
        tmp_path = tmp.name

    try:
        with pytest.raises(RuleLoadingError, match="Port number 99999 is out of valid range"):
            load_rules_from_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_filter_rules_by_category_and_severity():
    engine = ExposureEngine(include_builtin=True)
    db_rules = engine.list_rules(category=FindingCategory.DATABASE_EXPOSURE)
    assert len(db_rules) >= 4
    for r in db_rules:
        assert r.category == FindingCategory.DATABASE_EXPOSURE

    crit_rules = engine.list_rules(severity=SeverityLevel.CRITICAL)
    assert any(r.id == "EXP-MGMT-DOCKER" for r in crit_rules)
