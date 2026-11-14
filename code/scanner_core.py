"""Shared Nmap parsing and evidence-aware vulnerability matching."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class ServiceRecord:
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    hostname: str = ""


@dataclass(frozen=True)
class VulnerabilityRule:
    rule_id: str
    finding: str
    cvss: float
    exploited: bool
    ports: frozenset[int]
    service_pattern: Optional[str] = None
    product_pattern: Optional[str] = None
    version_pattern: Optional[str] = None
    evidence_type: str = "heuristic"

    def matches(self, service: ServiceRecord) -> bool:
        if service.port not in self.ports:
            return False
        for pattern, value in (
            (self.service_pattern, service.service),
            (self.product_pattern, service.product),
            (self.version_pattern, service.version),
        ):
            if pattern and not re.search(pattern, value, re.IGNORECASE):
                return False
        return True


RULES = (
    VulnerabilityRule(
        "vsftpd-2.3.4", "CVE-2011-2523", 10.0, True, frozenset({21}),
        product_pattern=r"vsftpd", version_pattern=r"2\.3\.4",
        evidence_type="version-match",
    ),
    VulnerabilityRule(
        "ssh-version-disclosure", "CWE-200", 2.1, False, frozenset({22}),
        service_pattern=r"ssh", evidence_type="service-exposure",
    ),
    VulnerabilityRule(
        "samba-3.0.20", "CVE-2007-2447", 9.3, True, frozenset({445}),
        product_pattern=r"samba", version_pattern=r"3\.0\.20",
        evidence_type="version-match",
    ),
    VulnerabilityRule(
        "metasploitable-bindshell", "Direct RCE", 10.0, True, frozenset({1524}),
        evidence_type="port-heuristic",
    ),
    VulnerabilityRule(
        "mysql-weak-auth", "CWE-521", 8.1, True, frozenset({3306}),
        service_pattern=r"mysql", evidence_type="port-heuristic",
    ),
    VulnerabilityRule(
        "postgres-weak-auth", "Weak Auth", 7.5, True, frozenset({5432}),
        service_pattern=r"postgres", evidence_type="port-heuristic",
    ),
    VulnerabilityRule(
        "unrealircd-3.2.8.1", "CVE-2010-2075", 10.0, True, frozenset({6667}),
        product_pattern=r"unrealircd", version_pattern=r"3\.2\.8\.1",
        evidence_type="version-match",
    ),
)


def parse_nmap_xml(xml_path: str | Path) -> tuple[list[ServiceRecord], dict[str, str]]:
    """Parse open Nmap services and scan metadata from an XML file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    metadata = {
        "scanner": "nmap",
        "version": root.get("version", ""),
        "start": root.get("startstr", ""),
        "source": str(xml_path),
    }
    services: list[ServiceRecord] = []
    for host in root.findall("host"):
        address = next(
            (element for element in host.findall("address")
             if element.get("addrtype") in (None, "ipv4", "ipv6")),
            host.find("address"),
        )
        if address is None or not address.get("addr"):
            continue
        hostnames = [
            item.get("name", "")
            for item in host.findall("hostnames/hostname")
            if item.get("name")
        ]
        hostname = hostnames[0] if hostnames else ""
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append(
                ServiceRecord(
                    ip=address.get("addr", ""),
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", ""),
                    state=state.get("state", ""),
                    service=service.get("name", "unknown") if service is not None else "unknown",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                    hostname=hostname,
                )
            )
    return services, metadata


def match_vulnerabilities(services: list[ServiceRecord]) -> list[tuple[ServiceRecord, VulnerabilityRule]]:
    """Return one deterministic finding per service/rule match."""
    matches: list[tuple[ServiceRecord, VulnerabilityRule]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for service in services:
        for rule in RULES:
            key = (service.ip, service.port, service.protocol, rule.rule_id)
            if rule.matches(service) and key not in seen:
                matches.append((service, rule))
                seen.add(key)
    return matches
