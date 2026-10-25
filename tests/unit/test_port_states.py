"""Unit tests for PortState distinctions, semantics, and telemetry serialization."""

from reconforge.core.enums import PortState, ScanStatus, TransportProtocol
from reconforge.core.models import PortObservation, ScanSummary


def test_port_states_distinct():
    """Verify that timeout is not conflated with filtered or closed."""
    assert PortState.TIMEOUT != PortState.FILTERED
    assert PortState.TIMEOUT != PortState.CLOSED
    assert PortState.OPEN != PortState.CLOSED
    assert PortState.NOT_SCANNED != PortState.ERROR


def test_port_observation_serialization():
    obs = PortObservation(
        target_ip="192.168.1.10",
        hostname="router.local",
        port=443,
        protocol=TransportProtocol.TCP,
        state=PortState.OPEN,
        response_time_ms=12.4,
        source="internal_tcp_connect",
    )
    data = obs.model_dump()
    assert data["target_ip"] == "192.168.1.10"
    assert data["port"] == 443
    assert data["state"] == "open"
    assert data["response_time_ms"] == 12.4

    # Reconstitute from dict
    obs2 = PortObservation(**data)
    assert obs2.state == PortState.OPEN


def test_scan_summary_statistics():
    summary = ScanSummary(
        targets_assessed=5,
        probes_attempted=100,
        open_count=3,
        closed_count=90,
        filtered_count=2,
        timeout_count=5,
        unreachable_count=0,
        error_count=0,
        duration_seconds=1.45,
        status=ScanStatus.COMPLETED,
    )
    assert summary.open_count == 3
    assert summary.targets_assessed == 5
    assert summary.status == ScanStatus.COMPLETED
