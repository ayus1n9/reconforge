"""Security tests: Rule safety, injection prevention, and parser limits."""

import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from reconforge.assessment.custom_rules import RuleLoadingError, load_rules_from_file
from reconforge.assessment.models import RuleCondition


def test_reject_oversized_regex_pattern():
    huge_pattern = "a" * 501
    with pytest.raises(
        ValidationError, match="Regular expression pattern exceeds 500 character limit"
    ):
        RuleCondition(version_pattern=huge_pattern)


def test_reject_invalid_regex_syntax():
    with pytest.raises(ValidationError, match="Invalid regular expression"):
        RuleCondition(version_pattern="[a-z(")


def test_reject_oversized_rule_file():
    # Create file > 1MB
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write("# " + ("A" * (1024 * 1024 + 100)))
        tmp_path = tmp.name

    try:
        with pytest.raises(RuleLoadingError, match="exceeds maximum allowable size"):
            load_rules_from_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_block_yaml_code_execution_gadgets():
    # YAML arbitrary Python object instantiation gadget (blocked by yaml.safe_load)
    malicious_yaml = """
id: EXP-EXPLOIT
name: Exploit
description: Test
severity: high
category: network_exposure
conditions:
  ports: [80]
remediation: !!python/object/apply:os.system ["id"]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(malicious_yaml)
        tmp_path = tmp.name

    try:
        with pytest.raises(RuleLoadingError, match="YAML parsing error"):
            load_rules_from_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
