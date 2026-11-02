"""Comprehensive end-to-end smoke test exercising all ReconForge CLI subcommands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from reconforge.cli import app

runner = CliRunner()


def test_cli_version_smoke():
    """Verify reconforge version human panel and json outputs."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ReconForge Security Intelligence Platform v1.0.0" in result.output
    assert "Web Dashboard: Bundled & Ready" in result.output

    json_result = runner.invoke(app, ["version", "--json"])
    assert json_result.exit_code == 0
    data = json.loads(json_result.output)
    assert data["version"] == "1.0.0"
    assert data["web_dashboard_available"] is True
    assert data["rules_count"] >= 15


def test_cli_validate_scope_smoke(tmp_path: Path):
    """Verify reconforge validate-scope command."""
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text(
        """
allowed_targets:
  - "127.0.0.1"
  - "192.168.1.0/24"
allowed_ports: "80,443,8000"
allow_public_targets: false
"""
    )
    result = runner.invoke(app, ["validate-scope", str(scope_yaml)])
    assert result.exit_code == 0
    assert "Scope definition is valid and enforceable" in result.output


def test_cli_e2e_workflow_smoke(tmp_path: Path):
    """Run full CLI lifecycle: scan -> assess -> score -> report -> snapshot -> diff."""
    # 1. Scan command 1 (creates database assessment 1)
    scan_res1 = runner.invoke(
        app,
        ["scan", "127.0.0.1", "-p", "65534", "--yes", "--json", "--timeout", "0.5"],
    )
    assert scan_res1.exit_code == 0
    data1 = json.loads(scan_res1.output)
    assessment_id1 = data1["summary"]["scan_id"]
    assert assessment_id1

    # 2. Assess command (evaluates rules on existing assessment)
    assess_res = runner.invoke(app, ["assess", assessment_id1])
    assert assess_res.exit_code == 0

    # 3. Score command
    score_res = runner.invoke(app, ["score", assessment_id1])
    assert score_res.exit_code == 0

    # 4. Report generate command
    report_file = tmp_path / "report.json"
    rep_res = runner.invoke(
        app,
        [
            "report",
            "generate",
            assessment_id1,
            "--format",
            "json",
            "--output",
            str(report_file),
        ],
    )
    assert rep_res.exit_code == 0
    assert report_file.exists()

    # 5. Snapshot export command
    snapshot_file1 = tmp_path / "snap1.json"
    snap_res = runner.invoke(
        app,
        [
            "snapshot",
            "export",
            assessment_id1,
            "--output",
            str(snapshot_file1),
        ],
    )
    assert snap_res.exit_code == 0
    assert snapshot_file1.exists()

    # 6. Scan command 2 (creates database assessment 2)
    scan_res2 = runner.invoke(
        app,
        ["scan", "127.0.0.1", "-p", "65534", "--yes", "--json", "--timeout", "0.5"],
    )
    assert scan_res2.exit_code == 0
    data2 = json.loads(scan_res2.output)
    assessment_id2 = data2["summary"]["scan_id"]
    assert assessment_id2

    # 7. Diff assessments command
    diff_res = runner.invoke(
        app,
        ["diff", assessment_id1, assessment_id2, "--json"],
    )
    assert diff_res.exit_code == 0
    diff_data = json.loads(diff_res.output)
    assert "risk" in diff_data
    assert "coverage" in diff_data

    # 8. Diff snapshots command
    snapshot_file2 = tmp_path / "snap2.json"
    runner.invoke(
        app,
        [
            "snapshot",
            "export",
            assessment_id2,
            "--output",
            str(snapshot_file2),
        ],
    )
    diff_snap_res = runner.invoke(
        app,
        ["diff-snapshots", str(snapshot_file1), str(snapshot_file2), "--json"],
    )
    assert diff_snap_res.exit_code == 0

    # 9. Serve command help check
    serve_help = runner.invoke(app, ["serve", "--help"])
    assert serve_help.exit_code == 0
    assert "--port" in serve_help.output
    assert "--api-key" in serve_help.output
