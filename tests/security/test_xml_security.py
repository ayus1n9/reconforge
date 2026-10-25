"""Security tests: XXE injection prevention and XML bomb defense in NmapAdapter."""

import pytest

from reconforge.core.exceptions import ScanError
from reconforge.fingerprinting.nmap_adapter import NmapAdapter

# Classical XML External Entity (XXE) Injection Payload
XXE_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="&xxe;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Billion Laughs (Recursive Entity Expansion) Denial-of-Service Payload
BILLION_LAUGHS_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="&lol3;"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_xxe_injection_blocked():
    """Verify defusedxml blocks external entity expansion in XML parsing."""
    adapter = NmapAdapter()
    # defusedxml will raise DTDForbidden / EntitiesForbidden which maps to ScanError
    with pytest.raises(ScanError):
        adapter.parse_nmap_xml(XXE_PAYLOAD)


def test_billion_laughs_bomb_blocked():
    """Verify defusedxml blocks recursive entity expansion attacks."""
    adapter = NmapAdapter()
    with pytest.raises(ScanError):
        adapter.parse_nmap_xml(BILLION_LAUGHS_PAYLOAD)
