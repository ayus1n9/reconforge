"""Safe loader and validator for user-defined custom YAML exposure rules."""

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from reconforge.assessment.models import ExposureRuleDefinition

logger = logging.getLogger("reconforge.assessment.custom_rules")

MAX_RULE_FILE_SIZE_BYTES = 1024 * 1024  # 1 MB boundary per rule file


class RuleLoadingError(Exception):
    """Raised when custom rule syntax or schema validation fails."""


def parse_and_validate_rule(
    raw_data: dict[str, Any], source_file: str = "<memory>"
) -> ExposureRuleDefinition:
    """Validate a raw dictionary against the ExposureRuleDefinition schema."""
    try:
        return ExposureRuleDefinition.model_validate(raw_data)
    except ValidationError as err:
        raise RuleLoadingError(
            f"Schema validation failed for rule in '{source_file}': {err}"
        ) from err


def load_rules_from_file(file_path: str | Path) -> list[ExposureRuleDefinition]:
    """Safely load and validate custom exposure rules from a YAML file."""
    path = Path(file_path).resolve()
    if not path.is_file():
        raise RuleLoadingError(f"Rule file '{path}' does not exist or is not a regular file.")

    if path.stat().st_size > MAX_RULE_FILE_SIZE_BYTES:
        raise RuleLoadingError(f"Rule file '{path}' exceeds maximum allowable size (1 MB).")

    try:
        with open(path, encoding="utf-8") as f:
            content = yaml.safe_load(f)
    except yaml.YAMLError as err:
        raise RuleLoadingError(f"YAML parsing error in '{path}': {err}") from err
    except Exception as err:
        raise RuleLoadingError(f"Failed to read rule file '{path}': {err}") from err

    if content is None:
        return []

    rules: list[ExposureRuleDefinition] = []
    # Support both single-rule YAML documents and multi-rule lists
    if isinstance(content, dict):
        # Could be single rule or dict with "rules" key
        if "rules" in content and isinstance(content["rules"], list):
            for idx, raw_rule in enumerate(content["rules"]):
                rules.append(parse_and_validate_rule(raw_rule, source_file=f"{path}#rule_{idx}"))
        else:
            rules.append(parse_and_validate_rule(content, source_file=str(path)))
    elif isinstance(content, list):
        for idx, raw_rule in enumerate(content):
            rules.append(parse_and_validate_rule(raw_rule, source_file=f"{path}#rule_{idx}"))
    else:
        raise RuleLoadingError(f"Invalid rule format in '{path}': expected mapping or list.")

    return rules


def load_rules_from_directory(
    dir_path: str | Path,
) -> tuple[list[ExposureRuleDefinition], list[str]]:
    """Recursively scan a directory for .yaml/.yml rule files and load them.

    Returns:
        tuple of (valid_rules, error_messages)
    """
    path = Path(dir_path).resolve()
    if not path.is_dir():
        return [], [f"Rules directory '{path}' not found."]

    valid_rules: list[ExposureRuleDefinition] = []
    errors: list[str] = []

    for file in sorted(path.rglob("*.y*ml")):
        try:
            loaded = load_rules_from_file(file)
            valid_rules.extend(loaded)
        except RuleLoadingError as err:
            logger.warning("Failed to load rule file: %s", err)
            errors.append(str(err))

    return valid_rules, errors
