"""Common Platform Enumeration (CPE 2.3) parser, generator, and service mapping engine."""

import re
from typing import Self

from pydantic import BaseModel, Field, field_validator


class CPE(BaseModel):
    """Structured representation of a NIST Common Platform Enumeration (CPE 2.3) identifier."""

    part: str = Field(
        default="a", description="CPE part: 'a' (application), 'o' (OS), or 'h' (hardware)."
    )
    vendor: str = Field(..., description="Organization or vendor name (normalized lowercase).")
    product: str = Field(..., description="Product name (normalized lowercase).")
    version: str = Field(default="*", description="Software release version or '*' for wildcard.")
    update: str = Field(default="*", description="Update or service pack identifier.")
    edition: str = Field(default="*", description="Legacy edition component.")
    language: str = Field(default="*", description="Language tag.")
    sw_edition: str = Field(
        default="*", description="Software edition (e.g. enterprise, community)."
    )
    target_sw: str = Field(default="*", description="Target software environment.")
    target_hw: str = Field(default="*", description="Target hardware architecture.")
    other: str = Field(default="*", description="Other vendor attributes.")

    @field_validator("part")
    @classmethod
    def validate_part(cls, v: str) -> str:
        clean = v.lower().strip()
        if clean not in {"a", "o", "h"}:
            raise ValueError(f"CPE part must be 'a', 'o', or 'h', got '{v}'")
        return clean

    @classmethod
    def _sanitize_component(cls, val: str | None, default: str = "*") -> str:
        if not val or val.strip() in {"", "*", "-"}:
            return default
        s = val.lower().strip()
        # Replace spaces with underscores and remove disallowed characters
        s = re.sub(r"\s+", "_", s)
        s = re.sub(r"[^a-z0-9_.\-]", "", s)
        return s or default

    def to_cpe23(self) -> str:
        """Serialize into standard NIST CPE 2.3 formatted string."""
        components = [
            "cpe:2.3",
            self.part,
            self._sanitize_component(self.vendor),
            self._sanitize_component(self.product),
            self._sanitize_component(self.version),
            self._sanitize_component(self.update),
            self._sanitize_component(self.edition),
            self._sanitize_component(self.language),
            self._sanitize_component(self.sw_edition),
            self._sanitize_component(self.target_sw),
            self._sanitize_component(self.target_hw),
            self._sanitize_component(self.other),
        ]
        return ":".join(components)

    def to_uri(self) -> str:
        """Serialize into legacy CPE 2.2 URI format."""
        v = self._sanitize_component(self.vendor)
        p = self._sanitize_component(self.product)
        ver = self._sanitize_component(self.version)
        if ver == "*":
            return f"cpe:/{self.part}:{v}:{p}"
        return f"cpe:/{self.part}:{v}:{p}:{ver}"

    @classmethod
    def from_string(cls, cpe_str: str) -> Self:
        """Parse a CPE 2.3 formatted string or CPE 2.2 URI into a CPE instance."""
        s = cpe_str.strip()
        if s.startswith("cpe:2.3:"):
            parts = s.split(":")
            if len(parts) < 5:
                raise ValueError(f"Invalid CPE 2.3 string (insufficient components): '{cpe_str}'")
            # Pad with wildcards if shorter than 12 components
            while len(parts) < 12:
                parts.append("*")
            return cls(
                part=parts[2],
                vendor=parts[3],
                product=parts[4],
                version=parts[5],
                update=parts[6],
                edition=parts[7],
                language=parts[8],
                sw_edition=parts[9],
                target_sw=parts[10],
                target_hw=parts[11],
                other=parts[12] if len(parts) > 12 else "*",
            )
        elif s.startswith("cpe:/"):
            # CPE 2.2 URI format
            remainder = s[5:]
            parts = remainder.split(":")
            if len(parts) < 3:
                raise ValueError(f"Invalid CPE 2.2 URI: '{cpe_str}'")
            part = parts[0]
            vendor = parts[1]
            product = parts[2]
            version = parts[3] if len(parts) > 3 else "*"
            return cls(part=part, vendor=vendor, product=product, version=version)
        else:
            raise ValueError(f"Unrecognized CPE string format: '{cpe_str}'")

    @classmethod
    def from_service(
        cls,
        service_name: str,
        product: str | None = None,
        version: str | None = None,
    ) -> Self:
        """Derive standard vendor and product CPE 2.3 attributes from discovered network services."""
        norm_svc = (service_name or "unknown").lower().strip()
        norm_prod = (product or "").lower().strip()
        norm_ver = cls._sanitize_component(version)

        # Mapping table for known network server software
        vendor_product_map = {
            "openssh": ("openssh", "openssh"),
            "dropbear": ("dropbear_ssh_project", "dropbear"),
            "apache": ("apache", "http_server"),
            "nginx": ("f5", "nginx"),
            "lighttpd": ("lighttpd", "lighttpd"),
            "redis": ("redis", "redis"),
            "mysql": ("oracle", "mysql"),
            "mariadb": ("mariadb", "mariadb"),
            "postgresql": ("postgresql", "postgresql"),
            "postgres": ("postgresql", "postgresql"),
            "mongodb": ("mongodb", "mongodb"),
            "elasticsearch": ("elastic", "elasticsearch"),
            "vsftpd": ("vsftpd_project", "vsftpd"),
            "proftpd": ("proftpd_project", "proftpd"),
            "pure-ftpd": ("pureftpd", "pure-ftpd"),
            "postfix": ("postfix", "postfix"),
            "exim": ("exim", "exim"),
            "sendmail": ("sendmail", "sendmail"),
            "docker": ("docker", "docker"),
            "kubernetes": ("kubernetes", "kubernetes"),
        }

        # Check product first, then service name
        matched_vendor: str | None = None
        matched_product: str | None = None

        for key, (v, p) in vendor_product_map.items():
            if key in norm_prod:
                matched_vendor, matched_product = v, p
                break

        if not matched_vendor:
            for key, (v, p) in vendor_product_map.items():
                if key in norm_svc:
                    matched_vendor, matched_product = v, p
                    break

        if not matched_vendor:
            # Clean fallback
            matched_vendor = cls._sanitize_component(norm_prod or norm_svc)
            matched_product = cls._sanitize_component(norm_prod or norm_svc)

        return cls(
            part="a",
            vendor=matched_vendor,
            product=matched_product,
            version=norm_ver,
        )
