"""Unit tests for NmapAdapter and XML normalization."""

import pytest

from reconforge.core.enums import ObservationConfidence
from reconforge.core.exceptions import ScanError
from reconforge.fingerprinting.nmap_adapter import NmapAdapter

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0p1" extrainfo="Ubuntu-1ubuntu1" method="probed">
          <cpe>cpe:/a:openbsd:openssh:9.0p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.22.0" method="probed"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_xml_parsing_normal():
    adapter = NmapAdapter(binary_path="/usr/bin/nmap")
    results = adapter.parse_nmap_xml(SAMPLE_NMAP_XML)

    assert len(results) == 2
    ip1, port1, fp1 = results[0]
    assert ip1 == "192.168.1.100"
    assert port1 == 22
    assert fp1.service_name == "ssh"
    assert fp1.product == "OpenSSH"
    assert fp1.version == "9.0p1"
    assert fp1.cpe_candidate == "cpe:/a:openbsd:openssh:9.0p1"
    assert fp1.source == "nmap"
    assert fp1.confidence == ObservationConfidence.HIGH

    ip2, port2, fp2 = results[1]
    assert ip2 == "192.168.1.100"
    assert port2 == 80
    assert fp2.service_name == "http"
    assert fp2.product == "nginx"
    assert fp2.version == "1.22.0"


def test_nmap_xml_parsing_malformed():
    adapter = NmapAdapter()
    with pytest.raises(ScanError, match="Nmap XML parsing failure"):
        adapter.parse_nmap_xml("<nmaprun><host><unclosed_tag></nmaprun>")


def test_nmap_availability_check():
    adapter = NmapAdapter(binary_path="/usr/bin/nmap")
    # /usr/bin/nmap exists in this environment
    assert adapter.is_available() is True

    adapter_fake = NmapAdapter(binary_path="/path/to/nonexistent/nmap_bin")
    assert adapter_fake.is_available() is False
