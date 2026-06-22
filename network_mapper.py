import csv
import html
import ipaddress
import json
import math
import platform
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, VERTICAL, W, X, Y, filedialog, messagebox, ttk
from typing import List
import tkinter as tk


APP_NAME = "DeepProbe"
APP_TAGLINE = "AI-assisted ethical network intelligence"

COMMON_PORTS = {
    20: ("ftp-data", "File transfer data"),
    21: ("ftp", "File transfer control"),
    22: ("ssh", "Remote shell"),
    23: ("telnet", "Unencrypted remote shell"),
    25: ("smtp", "Mail transfer"),
    53: ("dns", "Name service"),
    67: ("dhcp", "DHCP server"),
    68: ("dhcp", "DHCP client"),
    80: ("http", "Web server"),
    110: ("pop3", "Mail retrieval"),
    111: ("rpcbind", "RPC service mapper"),
    123: ("ntp", "Time service"),
    135: ("msrpc", "Windows RPC"),
    137: ("netbios-ns", "NetBIOS name"),
    138: ("netbios-dgm", "NetBIOS datagram"),
    139: ("netbios-ssn", "Windows file sharing"),
    143: ("imap", "Mail retrieval"),
    161: ("snmp", "Network management"),
    389: ("ldap", "Directory service"),
    443: ("https", "Encrypted web server"),
    445: ("smb", "Windows file sharing"),
    465: ("smtps", "Encrypted mail transfer"),
    500: ("ike", "VPN key exchange"),
    515: ("printer", "Line printer daemon"),
    587: ("submission", "Mail submission"),
    631: ("ipp", "Internet printing"),
    636: ("ldaps", "Encrypted directory service"),
    993: ("imaps", "Encrypted mail retrieval"),
    995: ("pop3s", "Encrypted mail retrieval"),
    1433: ("mssql", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle database"),
    1723: ("pptp", "VPN tunnel"),
    1883: ("mqtt", "IoT messaging"),
    2049: ("nfs", "Network file system"),
    2375: ("docker", "Docker API without TLS"),
    2376: ("docker-tls", "Docker API with TLS"),
    3306: ("mysql", "MySQL database"),
    3389: ("rdp", "Remote desktop"),
    5432: ("postgres", "PostgreSQL database"),
    5900: ("vnc", "Remote desktop"),
    5985: ("winrm", "Windows remote management"),
    5986: ("winrm-ssl", "Windows remote management SSL"),
    6379: ("redis", "Redis database"),
    8080: ("http-alt", "Alternate web server"),
    8443: ("https-alt", "Alternate encrypted web"),
    9200: ("elasticsearch", "Elasticsearch API"),
    9300: ("elasticsearch", "Elasticsearch transport"),
    11211: ("memcached", "Memcached database"),
    27017: ("mongodb", "MongoDB database"),
}

EXTENDED_EXTRA_PORTS = {
    7, 9, 13, 19, 37, 49, 69, 79, 88, 102, 113, 119, 179, 199, 264, 427,
    444, 514, 548, 554, 563, 873, 902, 989, 990, 1025, 1026, 1027, 1028,
    1029, 1080, 1194, 1241, 1434, 1604, 1812, 1813, 1900, 2082, 2083,
    2086, 2087, 2222, 2483, 2484, 3128, 3268, 3269, 3690, 4443, 4567,
    5000, 5001, 5060, 5061, 5353, 5601, 5672, 5800, 6000, 6667, 7001,
    7002, 8000, 8008, 8081, 8088, 8090, 8181, 8888, 9000, 9092, 10000,
    15672, 24800, 50000, 50070,
}

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 587,
    636, 993, 995, 1433, 1521, 1723, 1883, 2049, 2375, 3306, 3389, 5432,
    5900, 5985, 6379, 8080, 8443, 9200, 11211, 27017,
]

EXTENDED_PORTS = sorted(set(QUICK_PORTS) | EXTENDED_EXTRA_PORTS)
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8090, 8181, 8443, 8888, 9000}
TLS_PORTS = {443, 465, 563, 587, 636, 989, 990, 993, 995, 2083, 2087, 3269, 4443, 5061, 5986, 8443}
UDP_CHECK_PORTS = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    123: b"\x1b" + (b"\x00" * 47),
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x72\x6f\x62\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
}

RISKY_PORTS = {
    21: "FTP may expose credentials unless protected.",
    23: "Telnet sends credentials in clear text.",
    135: "RPC exposure can reveal Windows internals.",
    139: "NetBIOS exposure can leak shares and host data.",
    161: "SNMP often leaks network configuration.",
    445: "SMB should be tightly scoped and patched.",
    1433: "Database service exposed on the network.",
    1521: "Database service exposed on the network.",
    2375: "Docker API without TLS is high risk.",
    3306: "Database service exposed on the network.",
    3389: "RDP should be restricted and MFA protected.",
    5432: "Database service exposed on the network.",
    5900: "VNC commonly lacks strong access controls.",
    5985: "WinRM should be restricted to admin networks.",
    6379: "Redis should not be broadly reachable.",
    9200: "Elasticsearch API should be protected.",
    11211: "Memcached can leak data or aid amplification.",
    27017: "MongoDB should not be broadly reachable.",
}

SERVICE_DETAILS = {
    21: "FTP is used to transfer files. It is often risky because credentials and files may be sent without strong protection unless FTPS is configured.",
    22: "SSH provides encrypted remote shell and file transfer access. Check for key-only login, disabled root login, and patched server versions.",
    23: "Telnet provides remote shell access without encryption. It should normally be disabled on modern networks.",
    25: "SMTP is used to transfer email between mail servers. Check relay restrictions, banner leakage, and mail security controls.",
    53: "DNS resolves names to IP addresses. Check whether recursion, zone transfers, or internal records are exposed.",
    80: "HTTP serves web content without transport encryption. Check for admin panels, default pages, missing redirects, and outdated web software.",
    110: "POP3 retrieves email from a mailbox. Plain POP3 can expose credentials unless protected by TLS.",
    111: "RPCbind maps RPC services on Unix/Linux systems. It can reveal NFS and other network services.",
    123: "NTP provides time synchronization. Exposed NTP should be restricted to prevent abuse and information leakage.",
    135: "Microsoft RPC Endpoint Mapper supports Windows remote management and service discovery. Exposure should be tightly limited.",
    139: "NetBIOS Session Service supports legacy Windows file and printer sharing. It can expose host and share information.",
    143: "IMAP retrieves email from a mailbox. Plain IMAP can expose credentials unless protected by TLS.",
    161: "SNMP exposes network and device management data. Weak community strings can leak configuration and inventory.",
    389: "LDAP provides directory queries, commonly Active Directory. Check anonymous binds, TLS usage, and access controls.",
    443: "HTTPS serves encrypted web content. Check certificate health, server headers, app exposure, and authentication controls.",
    445: "SMB provides Windows file sharing and domain services. Check patch level, share permissions, signing, and segmentation.",
    587: "SMTP Submission is used by mail clients to send email. Check authentication, TLS, and relay restrictions.",
    636: "LDAPS provides encrypted LDAP directory access. Check certificate trust and directory access controls.",
    993: "IMAPS provides encrypted mailbox retrieval. Check TLS strength and exposed mail server version.",
    995: "POP3S provides encrypted mailbox retrieval. Check TLS strength and exposed mail server version.",
    1433: "Microsoft SQL Server database service. It should be reachable only from trusted application or admin networks.",
    1521: "Oracle database listener. Check listener security, patch level, and network access restrictions.",
    1723: "PPTP VPN service. PPTP is considered weak and should generally be replaced with stronger VPN protocols.",
    1883: "MQTT messaging service, often used by IoT systems. Check anonymous access and topic permissions.",
    2049: "NFS provides Unix/Linux network file sharing. Check exports, root squash, and client restrictions.",
    2375: "Docker API without TLS. If reachable, it can allow remote container and host control and should be treated as critical.",
    2376: "Docker API with TLS. Verify mutual TLS, authorization, and limited network exposure.",
    3306: "MySQL or MariaDB database service. Restrict exposure and enforce strong authentication.",
    3389: "Remote Desktop Protocol provides Windows GUI remote access. Restrict with VPN, MFA, lockout policies, and monitoring.",
    5432: "PostgreSQL database service. Restrict exposure and enforce strong authentication plus TLS where needed.",
    5900: "VNC provides remote desktop access. Many deployments have weak authentication or no encryption by default.",
    5985: "WinRM HTTP supports Windows remote management. Restrict to admin networks and require strong authentication.",
    5986: "WinRM HTTPS supports encrypted Windows remote management. Verify certificate and access controls.",
    6379: "Redis in-memory datastore. It should not be exposed broadly and must require authentication where supported.",
    8080: "Alternate HTTP service, commonly proxy, admin console, or application server. Check for default credentials and admin paths.",
    8443: "Alternate HTTPS service, commonly admin console or application server. Check certificate, authentication, and exposed panels.",
    9200: "Elasticsearch HTTP API. Exposed clusters can leak or modify data if not secured.",
    9300: "Elasticsearch transport port. Restrict to cluster nodes only.",
    11211: "Memcached cache service. It should not be internet- or broad-network-facing.",
    27017: "MongoDB database service. Restrict exposure, require authentication, and verify bind address.",
}


PORT_RECOMMENDATIONS = {
    21: "Replace FTP with SFTP/FTPS, disable anonymous login, and restrict file-transfer access to trusted networks.",
    22: "Harden SSH with key-based authentication, disabled root login, strong ciphers, and allow-list based access.",
    23: "Disable Telnet and migrate administration to SSH or another encrypted management channel.",
    25: "Restrict SMTP relay, require authentication/TLS where appropriate, and monitor for abuse.",
    53: "Disable open recursion, restrict zone transfers, and allow DNS queries only from expected networks.",
    80: "Redirect HTTP to HTTPS, patch the web stack, and review exposed paths for default or admin content.",
    110: "Prefer POP3S or another encrypted mail retrieval method and disable clear-text authentication.",
    135: "Limit RPC exposure to trusted Windows management networks and keep hosts fully patched.",
    139: "Block NetBIOS across network boundaries and remove legacy file-sharing dependencies where possible.",
    143: "Prefer IMAPS and disable clear-text mail authentication.",
    161: "Restrict SNMP to monitoring hosts, rotate community strings, and prefer SNMPv3.",
    389: "Prefer LDAPS or StartTLS and restrict LDAP queries to trusted systems.",
    445: "Restrict SMB to trusted VLANs, require SMB signing where possible, and verify patch posture.",
    1433: "Bind SQL Server to private interfaces, require strong authentication, and limit access with firewall rules.",
    1521: "Restrict Oracle listener access, enforce strong database authentication, and review exposed services.",
    1883: "Require MQTT authentication/TLS and limit broker access to approved IoT or application networks.",
    2049: "Restrict NFS exports to trusted clients and avoid broad read/write exports.",
    2375: "Immediately disable unauthenticated Docker TCP access or require mutual TLS on a restricted interface.",
    3306: "Bind MySQL to private interfaces, require strong credentials, and block internet or user-LAN access.",
    3389: "Place RDP behind VPN or zero-trust access, require MFA, and monitor failed login attempts.",
    5432: "Bind PostgreSQL to private interfaces, restrict pg_hba.conf, and enforce strong authentication.",
    5900: "Disable exposed VNC or require VPN, strong unique credentials, and encrypted transport.",
    5985: "Restrict WinRM to admin networks and prefer HTTPS WinRM with audited authentication.",
    6379: "Bind Redis to localhost/private networks, require authentication, and disable dangerous commands if exposed.",
    8080: "Review the alternate web service for default credentials, admin consoles, and missing authentication.",
    8443: "Validate TLS configuration and confirm the management or application console is not broadly exposed.",
    9200: "Require authentication/TLS for Elasticsearch and restrict API access to application or admin networks.",
    11211: "Bind Memcached to localhost/private networks and block UDP/TCP exposure outside trusted tiers.",
    27017: "Require MongoDB authentication/TLS and restrict access to application hosts only.",
}

BASELINE_RECOMMENDATIONS = [
    "Maintain an asset owner, business role, and approved exposure record for this host.",
    "Keep the operating system, firmware, and exposed services patched on a defined maintenance schedule.",
    "Apply least-privilege firewall rules so only required source networks can reach each service.",
    "Enable centralized logging and alerting for authentication failures, service errors, and configuration changes.",
    "Back up critical configurations and test restore procedures regularly.",
]


PORT_ATTACK_PROFILES = {
    21: {
        "weakness": "Clear-text file transfer or weak anonymous access.",
        "attack": "Credential interception, anonymous data access, or malicious file upload if write access is enabled.",
        "impact": "Sensitive files, credentials, or deployment artifacts may be exposed or modified.",
    },
    22: {
        "weakness": "Remote administration surface exposed.",
        "attack": "Password spraying, brute-force login attempts, or abuse of weak SSH configuration.",
        "impact": "Successful compromise can provide interactive shell access to the host.",
    },
    23: {
        "weakness": "Unencrypted remote administration.",
        "attack": "Credential sniffing and session hijacking on any network path that can observe traffic.",
        "impact": "Administrative credentials and command sessions can be captured in clear text.",
    },
    25: {
        "weakness": "Mail transfer service reachable.",
        "attack": "Open relay abuse, spoofed mail delivery, or user/service enumeration if misconfigured.",
        "impact": "Reputation damage, phishing relay abuse, and leakage of mail infrastructure details.",
    },
    53: {
        "weakness": "DNS service reachable.",
        "attack": "Open recursion abuse, DNS amplification, zone transfer leakage, or internal name discovery.",
        "impact": "Network names, internal structure, or bandwidth can be abused by attackers.",
    },
    80: {
        "weakness": "Unencrypted web application or management surface.",
        "attack": "Credential capture, session downgrade, default page discovery, or web application probing.",
        "impact": "Application data, admin panels, or user sessions may be exposed.",
    },
    110: {
        "weakness": "Legacy clear-text mail retrieval.",
        "attack": "Credential interception or mailbox access attempts against weak authentication.",
        "impact": "Email contents and reusable passwords may be exposed.",
    },
    135: {
        "weakness": "Windows RPC endpoint mapper exposed.",
        "attack": "Service enumeration and targeting of vulnerable Windows management services.",
        "impact": "Attackers can map Windows internals and identify lateral movement paths.",
    },
    139: {
        "weakness": "Legacy NetBIOS file-sharing surface.",
        "attack": "Share enumeration, host information leakage, and legacy authentication abuse.",
        "impact": "File shares and host metadata may leak across network boundaries.",
    },
    143: {
        "weakness": "Clear-text IMAP mail retrieval.",
        "attack": "Credential interception or mailbox brute-force attempts.",
        "impact": "Mailbox contents and authentication secrets may be exposed.",
    },
    161: {
        "weakness": "SNMP management service reachable.",
        "attack": "Community-string guessing and configuration or interface inventory extraction.",
        "impact": "Network topology, device configuration, and routing details can leak.",
    },
    389: {
        "weakness": "LDAP directory service reachable.",
        "attack": "Directory enumeration, weak bind abuse, or clear-text credential exposure without TLS.",
        "impact": "Users, groups, computers, and internal structure may be disclosed.",
    },
    445: {
        "weakness": "SMB file sharing and Windows management exposed.",
        "attack": "Share enumeration, credential relay, password spraying, or targeting of unpatched SMB flaws.",
        "impact": "File exposure, lateral movement, or remote code execution risk on vulnerable systems.",
    },
    1433: {
        "weakness": "Microsoft SQL Server reachable.",
        "attack": "Credential guessing, database enumeration, or abuse of weak database permissions.",
        "impact": "Business data can be read, changed, deleted, or used for further compromise.",
    },
    1521: {
        "weakness": "Oracle listener reachable.",
        "attack": "Database service enumeration and password attacks against exposed schemas.",
        "impact": "Sensitive database contents and application credentials may be exposed.",
    },
    1883: {
        "weakness": "MQTT broker reachable.",
        "attack": "Unauthorized topic subscription, message injection, or device command abuse.",
        "impact": "IoT telemetry, device control, or operational messages may be manipulated.",
    },
    2049: {
        "weakness": "NFS file-sharing service reachable.",
        "attack": "Export enumeration and unauthorized read/write access if client restrictions are weak.",
        "impact": "Files, backups, or application data may be exposed or tampered with.",
    },
    2375: {
        "weakness": "Docker API exposed without TLS.",
        "attack": "Unauthenticated container control, image manipulation, or host filesystem access through containers.",
        "impact": "Full host compromise is possible when Docker control is exposed.",
    },
    3306: {
        "weakness": "MySQL database reachable.",
        "attack": "Credential guessing, data extraction attempts, and abuse of weak database grants.",
        "impact": "Application data and credentials may be exposed or modified.",
    },
    3389: {
        "weakness": "Remote Desktop exposed.",
        "attack": "Password spraying, brute-force attempts, session hijacking risk, or exploitation of unpatched RDP flaws.",
        "impact": "Interactive desktop access can lead to full account or host compromise.",
    },
    5432: {
        "weakness": "PostgreSQL database reachable.",
        "attack": "Credential guessing, database enumeration, and abuse of exposed administrative roles.",
        "impact": "Application data can be extracted, changed, or used to pivot.",
    },
    5900: {
        "weakness": "VNC remote desktop reachable.",
        "attack": "Weak password attacks or interception when encryption is not enforced.",
        "impact": "Graphical desktop control may expose sensitive applications and credentials.",
    },
    5985: {
        "weakness": "WinRM management endpoint reachable.",
        "attack": "Credential attacks and remote command execution if valid credentials are obtained.",
        "impact": "Attackers can gain powerful Windows administration capability.",
    },
    6379: {
        "weakness": "Redis data store reachable.",
        "attack": "Unauthenticated data access, configuration abuse, or cache data extraction.",
        "impact": "Session data, application secrets, or service state may be exposed.",
    },
    8080: {
        "weakness": "Alternate web or admin service reachable.",
        "attack": "Default credential testing, exposed admin-console probing, or vulnerable web component targeting.",
        "impact": "Application control panels or management functions may be exposed.",
    },
    8443: {
        "weakness": "Encrypted alternate web or admin service reachable.",
        "attack": "Admin-console discovery, weak TLS review, or authentication bypass attempts against the application.",
        "impact": "Management interfaces may expose configuration or control of the system.",
    },
    9200: {
        "weakness": "Elasticsearch API reachable.",
        "attack": "Unauthenticated index enumeration, data extraction, or destructive API calls if access control is weak.",
        "impact": "Search indexes can leak sensitive data or be deleted.",
    },
    11211: {
        "weakness": "Memcached service reachable.",
        "attack": "Cache data extraction or reflection/amplification abuse when exposed broadly.",
        "impact": "Cached secrets may leak and the host may be abused in network attacks.",
    },
    27017: {
        "weakness": "MongoDB database reachable.",
        "attack": "Credential attacks, exposed database enumeration, or data modification when auth is weak.",
        "impact": "Document data may be stolen, altered, or deleted.",
    },
}


@dataclass
class PortFinding:
    port: int
    service: str
    description: str
    protocol: str = "tcp"
    banner: str = ""
    risk: str = ""
    evidence: str = ""
    severity: str = "info"


@dataclass
class HostFinding:
    ip: str
    hostname: str = ""
    alive: bool = False
    latency_ms: float = 0.0
    os_guess: str = "Unknown"
    mac: str = ""
    vendor: str = ""
    ports: List[PortFinding] = field(default_factory=list)
    udp_findings: List[PortFinding] = field(default_factory=list)
    fingerprints: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    trace: List[str] = field(default_factory=list)
    ttl_hint: str = ""
    intelligence: str = ""

    @property
    def risk_score(self) -> int:
        score = 0
        for item in self.ports + self.udp_findings:
            if item.severity == "critical":
                score += 25
            elif item.severity == "high":
                score += 18
            elif item.port in RISKY_PORTS:
                score += 12
            elif item.port in {80, 443, 8080, 8443}:
                score += 2
            else:
                score += 4
        return min(score, 100)

    @property
    def risk_label(self) -> str:
        if self.risk_score >= 50:
            return "High"
        if self.risk_score >= 20:
            return "Medium"
        if self.risk_score > 0:
            return "Low"
        return "None"


class ScanCancelled(Exception):
    pass


def classify_port_severity(port, banner, protocol):
    if port == 2375:
        return "critical"
    if port in {23, 445, 3389, 5900, 5985, 6379, 9200, 11211, 27017}:
        return "high"
    if port in {21, 135, 139, 1433, 1521, 3306, 5432}:
        return "medium"
    if protocol == "udp" and port in {53, 123, 161}:
        return "medium"
    if banner and any(token in banner.lower() for token in ["default", "unauthorized", "anonymous", "test page"]):
        return "medium"
    return "info"


def describe_service(port, service, description):
    return SERVICE_DETAILS.get(
        port,
        f"{service.upper()} was detected. {description}. Verify the owning application, required exposure, authentication, and patch level.",
    )


def port_value(item, name, default=""):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def get_port_attack_profile(item):
    port = port_value(item, "port", 0)
    severity = port_value(item, "severity", "info")
    risk = port_value(item, "risk", "")
    profile = PORT_ATTACK_PROFILES.get(port)
    if profile:
        return profile
    if port in WEB_PORTS:
        return {
            "weakness": "Web service is reachable from the scanned network.",
            "attack": "Application probing, default-content discovery, authentication attacks, or vulnerable component targeting.",
            "impact": "Web data, user sessions, or administrative functions may be exposed if the application is weak.",
        }
    if port in TLS_PORTS:
        return {
            "weakness": "Encrypted service is reachable and should be configuration-reviewed.",
            "attack": "Weak TLS, certificate, or exposed-login review by an attacker looking for downgrade or access-control gaps.",
            "impact": "Misconfiguration can expose sensitive traffic or protected management functions.",
        }
    if severity in {"critical", "high", "medium"}:
        return {
            "weakness": risk or "Potentially sensitive network service is reachable.",
            "attack": "Service fingerprinting, credential attacks, or exploitation of unpatched software may be attempted.",
            "impact": "Impact depends on the service role, but exposure can support compromise or lateral movement.",
        }
    return {
        "weakness": "Service is open and reachable from the scan location.",
        "attack": "Attackers can fingerprint the service and test it for weak configuration or outdated software.",
        "impact": "Risk is lower by default, but unnecessary exposure increases the attack surface.",
    }


def format_port_attack_analysis(item):
    port = port_value(item, "port", 0)
    profile = get_port_attack_profile(item)
    recommendation = PORT_RECOMMENDATIONS.get(
        port,
        "Validate business need, patch level, authentication, logging, and source-network restrictions.",
    )
    return [
        f"Weakness: {profile['weakness']}",
        f"Possible attack: {profile['attack']}",
        f"Impact: {profile['impact']}",
        f"Defense: {recommendation}",
    ]


def analyze_host(ip, hostname, tcp_ports, udp_findings, ttl_hint):
    all_ports = tcp_ports + udp_findings
    port_numbers = {item.port for item in all_ports}
    fingerprints = []
    findings = []
    recommendations = []

    if hostname:
        fingerprints.append(f"Reverse DNS resolved to {hostname}.")
    if ttl_hint:
        fingerprints.append(ttl_hint + ".")
    for item in all_ports:
        fingerprints.append(f"{item.protocol.upper()} {item.port}/{item.service}: {describe_service(item.port, item.service, item.description)}")
        if item.evidence:
            fingerprints.append(f"{item.protocol.upper()} {item.port}: {item.evidence}.")
        if item.banner:
            fingerprints.append(f"{item.protocol.upper()} {item.port} banner: {item.banner[:140]}.")
        if item.port in PORT_RECOMMENDATIONS:
            recommendations.append(f"{item.severity.upper()} {item.port}/{item.protocol}: {PORT_RECOMMENDATIONS[item.port]}")
        elif item.severity in {"critical", "high", "medium"}:
            recommendations.append(
                f"{item.severity.upper()} {item.port}/{item.protocol}: Validate the service owner, patch level, "
                "authentication strength, and source-network restrictions."
            )

    if {135, 139, 445} & port_numbers:
        findings.append("Windows management or file-sharing surface is reachable.")
        recommendations.append("HIGH Windows services: Restrict SMB/RPC to trusted admin VLANs and verify patch level.")
    if 3389 in port_numbers:
        findings.append("Remote Desktop is exposed.")
        recommendations.append("HIGH RDP: Place RDP behind VPN or zero-trust access, enable MFA, and monitor login failures.")
    if 23 in port_numbers:
        findings.append("Telnet is reachable and transmits credentials without encryption.")
        recommendations.append("HIGH Telnet: Disable Telnet and replace it with SSH using key-based authentication.")
    if 21 in port_numbers:
        findings.append("FTP is reachable.")
        recommendations.append("MEDIUM FTP: Disable anonymous FTP and prefer SFTP/FTPS for file transfer.")
    if {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017} & port_numbers:
        findings.append("Database or data-store service is reachable from the scanned network.")
        recommendations.append("HIGH data services: Bind databases to private interfaces and enforce network ACLs plus authentication.")
    if 2375 in port_numbers:
        findings.append("Docker API without TLS appears reachable.")
        recommendations.append("CRITICAL Docker API: Immediately disable unauthenticated Docker TCP access or require mutual TLS.")
    if {80, 443, 8080, 8443, 8000, 8081, 8888} & port_numbers:
        findings.append("Web management or application service is reachable.")
        recommendations.append("MEDIUM web services: Review HTTP headers, authentication, default pages, and exposed admin paths.")
    if {53, 123, 161} & {item.port for item in udp_findings}:
        findings.append("UDP infrastructure service responded.")
        recommendations.append("MEDIUM UDP services: Limit recursive DNS, NTP, and SNMP exposure; rotate SNMP community strings.")

    high_count = sum(1 for item in all_ports if item.severity in {"critical", "high"})
    medium_count = sum(1 for item in all_ports if item.severity == "medium")
    if not findings and all_ports:
        findings.append("Host is reachable with limited obvious exposure from this scan profile.")
        recommendations.append("Run an authenticated assessment for software inventory and patch accuracy.")
    if not all_ports:
        findings.append("No selected TCP or UDP services responded.")
        recommendations.append("Confirm host firewall policy and rerun with a broader profile if needed.")
    recommendations.extend(BASELINE_RECOMMENDATIONS)

    intelligence = (
        f"DeepProbe AI Intel: {ip} has {len(tcp_ports)} TCP and {len(udp_findings)} UDP finding(s). "
        f"Priority signals: {high_count} high/critical and {medium_count} medium exposure(s). "
        f"Most likely role: {infer_role(port_numbers)}. "
        f"Recommended next action: {recommendations[0] if recommendations else 'Validate asset ownership and patch state.'}"
    )
    return fingerprints[:12], dedupe(findings), dedupe(recommendations), intelligence


def infer_role(port_numbers):
    if {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017} & port_numbers:
        return "data service"
    if {135, 139, 445, 3389, 5985, 5986} & port_numbers:
        return "Windows endpoint/server"
    if {80, 443, 8080, 8443, 8000, 8888} & port_numbers:
        return "web application or appliance"
    if {22, 111, 2049} & port_numbers:
        return "Linux/Unix service host"
    if {53, 123, 161} & port_numbers:
        return "network infrastructure"
    return "unknown or lightly exposed asset"


def dedupe(items):
    result = []
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


class NetworkScanner:
    def __init__(self, progress_queue, stop_event):
        self.progress_queue = progress_queue
        self.stop_event = stop_event

    def scan(self, targets, ports, scan_dead_hosts, timeout, workers, udp_enabled=False, trace_enabled=False, banner_enabled=True):
        addresses = self._expand_targets(targets)
        total = max(len(addresses), 1)
        self._log(f"Expanded target set to {len(addresses)} address(es).")
        results = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._scan_host,
                    ip,
                    ports,
                    scan_dead_hosts,
                    timeout,
                    udp_enabled,
                    trace_enabled,
                    banner_enabled,
                ): ip
                for ip in addresses
            }
            for done_count, future in enumerate(as_completed(futures), start=1):
                if self.stop_event.is_set():
                    raise ScanCancelled()
                ip = futures[future]
                try:
                    host = future.result()
                    if host.alive or host.ports:
                        results.append(host)
                        self.progress_queue.put(("host", host))
                except Exception as exc:
                    self._log(f"{ip}: {exc}")
                self.progress_queue.put(("progress", done_count, total))

        return sorted(results, key=lambda item: ipaddress.ip_address(item.ip))

    def _expand_targets(self, targets):
        expanded = []
        for raw_target in targets.replace(",", "\n").splitlines():
            target = raw_target.strip()
            if not target:
                continue
            try:
                network = ipaddress.ip_network(target, strict=False)
                expanded.extend(str(ip) for ip in network.hosts())
                if network.num_addresses == 1:
                    expanded.append(str(network.network_address))
            except ValueError:
                try:
                    expanded.append(socket.gethostbyname(target))
                except socket.gaierror:
                    self._log(f"Could not resolve target: {target}")

        seen = set()
        unique = []
        for ip in expanded:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
        if len(unique) > 4096:
            raise ValueError("Target range is too large for this desktop scanner. Use /20 or smaller.")
        return unique

    def _scan_host(self, ip, ports, scan_dead_hosts, timeout, udp_enabled, trace_enabled, banner_enabled):
        if self.stop_event.is_set():
            raise ScanCancelled()

        alive, latency, ttl_hint = self._ping(ip, timeout)
        if not alive and not scan_dead_hosts:
            return HostFinding(ip=ip, alive=False)

        hostname = self._reverse_dns(ip)
        mac = lookup_arp_mac(ip)
        open_ports = []
        for port in ports:
            if self.stop_event.is_set():
                raise ScanCancelled()
            finding = self._probe_port(ip, port, timeout, banner_enabled)
            if finding:
                open_ports.append(finding)

        udp_findings = []
        if udp_enabled:
            for port in sorted(set(ports) & set(UDP_CHECK_PORTS)):
                finding = self._probe_udp(ip, port, timeout)
                if finding:
                    udp_findings.append(finding)

        trace = self._trace_route(ip, timeout) if trace_enabled and (alive or open_ports) else []
        fingerprints, findings, recommendations, intelligence = analyze_host(ip, hostname, open_ports, udp_findings, ttl_hint)

        return HostFinding(
            ip=ip,
            hostname=hostname,
            alive=alive or bool(open_ports),
            latency_ms=latency,
            os_guess=self._guess_os(open_ports, ttl_hint),
            mac=mac,
            ports=open_ports,
            udp_findings=udp_findings,
            fingerprints=fingerprints,
            findings=findings,
            recommendations=recommendations,
            trace=trace,
            ttl_hint=ttl_hint,
            intelligence=intelligence,
        )

    def _ping(self, ip, timeout):
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), ip]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=timeout + 1,
                check=False,
            )
            latency = (time.perf_counter() - started) * 1000
            ttl_hint = self._extract_ttl_hint(completed.stdout)
            return completed.returncode == 0, latency, ttl_hint
        except (subprocess.SubprocessError, OSError):
            return False, 0.0, ""

    def _extract_ttl_hint(self, output):
        match = re.search(r"ttl[=\s](\d+)", output or "", re.IGNORECASE)
        if not match:
            return ""
        ttl = int(match.group(1))
        if ttl <= 64:
            return "TTL suggests Linux/Unix-class host"
        if ttl <= 128:
            return "TTL suggests Windows-class host"
        return "TTL suggests network device or uncommon stack"

    def _probe_port(self, ip, port, timeout, banner_enabled=True):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(min(timeout, 1.0))
                service, description = COMMON_PORTS.get(port, ("unknown", "Unidentified TCP service"))
                banner = self._grab_banner(sock, port) if banner_enabled else ""
                extra_evidence = []
                if banner_enabled and port in WEB_PORTS:
                    web_info = self._probe_http(ip, port, timeout, port in TLS_PORTS)
                    if web_info:
                        extra_evidence.append(web_info)
                if banner_enabled and port in TLS_PORTS:
                    tls_info = self._probe_tls(ip, port, timeout)
                    if tls_info:
                        extra_evidence.append(tls_info)
                risk = RISKY_PORTS.get(port, "")
                severity = classify_port_severity(port, banner, "tcp")
                return PortFinding(
                    port=port,
                    service=service,
                    description=description,
                    protocol="tcp",
                    banner=banner,
                    risk=risk,
                    evidence=" | ".join(extra_evidence),
                    severity=severity,
                )
        except (OSError, socket.timeout):
            return None

    def _probe_udp(self, ip, port, timeout):
        payload = UDP_CHECK_PORTS.get(port, b"")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(payload, (ip, port))
                data, _address = sock.recvfrom(256)
                service, description = COMMON_PORTS.get(port, ("unknown", "UDP service"))
                return PortFinding(
                    port=port,
                    service=service,
                    description=description,
                    protocol="udp",
                    banner=data[:80].hex(" "),
                    risk=RISKY_PORTS.get(port, ""),
                    evidence="UDP response received",
                    severity=classify_port_severity(port, "", "udp"),
                )
        except (OSError, socket.timeout):
            return None

    def _grab_banner(self, sock, port):
        probes = {
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\n\r\n",
            8000: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"",
            8443: b"",
            21: b"",
            22: b"",
            25: b"EHLO scanner.local\r\n",
            110: b"",
            143: b"",
            587: b"EHLO scanner.local\r\n",
        }
        try:
            if port in probes and probes[port]:
                sock.sendall(probes[port])
            data = sock.recv(160)
            return data.decode("utf-8", errors="replace").strip().replace("\r", " ").replace("\n", " ")
        except OSError:
            return ""

    def _probe_http(self, ip, port, timeout, use_tls):
        scheme = "https" if use_tls else "http"
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                raw = context.wrap_socket(raw, server_hostname=ip)
            with raw:
                raw.settimeout(timeout)
                raw.sendall(b"GET / HTTP/1.0\r\nHost: probe.local\r\nUser-Agent: DeepProbe\r\n\r\n")
                data = raw.recv(2048).decode("utf-8", errors="replace")
            server = re.search(r"^Server:\s*(.+)$", data, re.IGNORECASE | re.MULTILINE)
            title = re.search(r"<title[^>]*>(.*?)</title>", data, re.IGNORECASE | re.DOTALL)
            parts = [f"{scheme.upper()} responsive"]
            if server:
                parts.append(f"Server={server.group(1).strip()[:80]}")
            if title:
                clean_title = re.sub(r"\s+", " ", title.group(1)).strip()
                parts.append(f"Title={clean_title[:80]}")
            return "; ".join(parts)
        except (OSError, ssl.SSLError, socket.timeout):
            return ""

    def _probe_tls(self, ip, port, timeout):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=ip) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
            parts = []
            if cipher:
                parts.append(f"TLS cipher={cipher[0]}")
            subject = cert.get("subject", []) if cert else []
            names = []
            for item in subject:
                for key, value in item:
                    if key == "commonName":
                        names.append(value)
            if names:
                parts.append(f"CN={names[0]}")
            return "; ".join(parts)
        except (OSError, ssl.SSLError, socket.timeout):
            return ""

    def _trace_route(self, ip, timeout):
        system = platform.system().lower()
        cmd = ["tracert", "-d", "-h", "8", "-w", str(int(timeout * 1000)), ip] if system == "windows" else [
            "traceroute", "-n", "-m", "8", "-w", str(max(int(timeout), 1)), ip
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout * 10, 6), check=False)
        except (subprocess.SubprocessError, OSError):
            return []
        hops = []
        for line in completed.stdout.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                hops.append(match.group(1))
            if len(hops) >= 8:
                break
        return hops

    def _reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def _guess_os(self, ports, ttl_hint=""):
        port_set = {item.port for item in ports}
        if {135, 139, 445} & port_set:
            return "Windows likely"
        if {22, 111, 2049} & port_set:
            return "Linux/Unix likely"
        if {548, 631} & port_set:
            return "macOS/Unix possible"
        if {80, 443, 8080, 8443} & port_set:
            return "Network appliance/web host"
        if "Windows" in ttl_hint:
            return "Windows possible"
        if "Linux" in ttl_hint:
            return "Linux/Unix possible"
        return "Unknown"

    def _log(self, message):
        self.progress_queue.put(("log", message))


def lookup_arp_mac(ip):
    try:
        completed = subprocess.run(
            ["arp", "-a", ip],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    for line in completed.stdout.splitlines():
        if ip in line:
            parts = line.split()
            for part in parts:
                if "-" in part and len(part) >= 17:
                    return part
                if ":" in part and len(part) >= 17:
                    return part
    return ""


def parse_ports(raw_value):
    value = raw_value.strip().lower()
    if value in {"quick", "top", "common"}:
        return QUICK_PORTS
    if value in {"deep", "extended", "advanced"}:
        return EXTENDED_PORTS
    if value in {"web", "http"}:
        return sorted(WEB_PORTS)
    if value in {"windows", "ad"}:
        return [53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 5986]
    if value in {"databases", "db"}:
        return [1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017]
    if value in {"all", "full"}:
        return list(range(1, 65536))

    ports = set()
    for part in value.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(ports)


class NetworkMapperApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DeepProbe // Ethical Network Intelligence")
        self.geometry("1360x820")
        self.minsize(1100, 700)
        self.configure(bg="#071013")

        self.results = []
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.events = queue.Queue()
        self.host_nodes = {}

        self._configure_style()
        self._build_ui()
        self.after(120, self._drain_events)

    def _configure_style(self):
        self.style = ttk.Style(self)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
        bg = "#071013"
        panel = "#0d1b1e"
        field = "#10262b"
        text = "#d7ffe8"
        accent = "#00ff9c"
        muted = "#8fb9a8"
        self.style.configure(".", background=bg, foreground=text, fieldbackground=field, font=("Segoe UI", 10))
        self.style.configure("TFrame", background=bg)
        self.style.configure("Panel.TFrame", background=panel, relief="flat")
        self.style.configure("TLabel", background=bg, foreground=text)
        self.style.configure("Muted.TLabel", background=bg, foreground=muted)
        self.style.configure("Title.TLabel", background=bg, foreground=accent, font=("Courier New", 30, "bold"))
        self.style.configure("Glitch.TLabel", background=bg, foreground="#39ff14", font=("Courier New", 11, "bold"))
        self.style.configure("SubTitle.TLabel", background=bg, foreground=muted, font=("Consolas", 10))
        self.style.configure("Metric.TLabel", background=bg, foreground=accent, font=("Consolas", 20, "bold"))
        self.style.configure("TButton", background="#12343a", foreground=text, bordercolor="#1ddf99", focusthickness=1)
        self.style.map("TButton", background=[("active", "#16505a")], foreground=[("active", "#ffffff")])
        self.style.configure("TCheckbutton", background=bg, foreground=text)
        self.style.configure("TEntry", fieldbackground=field, foreground=text, insertcolor=text)
        self.style.configure("TCombobox", fieldbackground=field, foreground=text, arrowcolor=accent)
        self.style.configure("Treeview", rowheight=28, background="#08171a", fieldbackground="#08171a", foreground=text)
        self.style.configure("Treeview.Heading", background="#12343a", foreground=accent, font=("Segoe UI", 10, "bold"))
        self.style.map("Treeview", background=[("selected", "#145a46")], foreground=[("selected", "#ffffff")])

    def _build_ui(self):
        main = ttk.Frame(self, padding=12)
        main.pack(fill=BOTH, expand=True)

        header = ttk.Frame(main)
        header.pack(fill=X, pady=(0, 10))
        brand = ttk.Frame(header)
        brand.pack(side=LEFT)
        ttk.Label(brand, text="[ D33PPR0B3 ]", style="Title.TLabel").pack(anchor=W)
        ttk.Label(brand, text="root@deepprobe:~# ethical_network_intel --authorized", style="Glitch.TLabel").pack(anchor=W)
        ttk.Label(header, text=f"  // {APP_TAGLINE}", style="SubTitle.TLabel").pack(side=LEFT, padx=(14, 0), pady=(22, 0))
        self.clock_var = tk.StringVar(value=datetime.now().strftime("%H:%M:%S"))
        ttk.Label(header, textvariable=self.clock_var, style="SubTitle.TLabel").pack(side=RIGHT, pady=(10, 0))
        self.after(1000, self._tick_clock)

        controls = ttk.Frame(main)
        controls.pack(fill=X)

        left = ttk.Frame(controls)
        left.pack(side=LEFT, fill=X, expand=True)

        ttk.Label(left, text="TARGETS").grid(row=0, column=0, sticky=W)
        self.targets_var = tk.StringVar(value=self._default_target())
        ttk.Entry(left, textvariable=self.targets_var).grid(row=1, column=0, sticky="ew", padx=(0, 8))

        ttk.Label(left, text="SCAN PROFILE / PORTS").grid(row=0, column=1, sticky=W)
        self.ports_var = tk.StringVar(value="deep")
        ttk.Combobox(
            left,
            textvariable=self.ports_var,
            values=["quick", "deep", "web", "windows", "databases", "20-1024", "80,443,445,3389,5985", "all"],
            width=24,
        ).grid(row=1, column=1, sticky="ew", padx=(0, 8))

        ttk.Label(left, text="TIMEOUT").grid(row=0, column=2, sticky=W)
        self.timeout_var = tk.DoubleVar(value=0.7)
        ttk.Spinbox(left, from_=0.2, to=5.0, increment=0.1, textvariable=self.timeout_var, width=8).grid(
            row=1, column=2, sticky=W, padx=(0, 8)
        )

        ttk.Label(left, text="THREADS").grid(row=0, column=3, sticky=W)
        self.workers_var = tk.IntVar(value=128)
        ttk.Spinbox(left, from_=8, to=512, increment=8, textvariable=self.workers_var, width=8).grid(
            row=1, column=3, sticky=W, padx=(0, 8)
        )

        self.scan_dead_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(left, text="TCP discovery when ping is blocked", variable=self.scan_dead_var).grid(
            row=2, column=0, sticky=W, pady=(8, 0)
        )
        self.banner_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(left, text="Deep banner + HTTP/TLS fingerprinting", variable=self.banner_var).grid(
            row=2, column=1, sticky=W, pady=(8, 0)
        )
        self.udp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="UDP-lite DNS/NTP/SNMP", variable=self.udp_var).grid(
            row=2, column=2, sticky=W, pady=(8, 0)
        )
        self.trace_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Trace route", variable=self.trace_var).grid(
            row=2, column=3, sticky=W, pady=(8, 0)
        )
        self.authorized_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Authorized ethical assessment", variable=self.authorized_var).grid(
            row=3, column=0, columnspan=2, sticky=W, pady=(8, 0)
        )
        left.columnconfigure(0, weight=3)
        left.columnconfigure(1, weight=1)

        buttons = ttk.Frame(controls)
        buttons.pack(side=RIGHT, padx=(10, 0))
        self.start_button = ttk.Button(buttons, text="INITIATE PROBE", command=self.start_scan)
        self.start_button.pack(fill=X)
        self.stop_button = ttk.Button(buttons, text="ABORT", command=self.stop_scan, state="disabled")
        self.stop_button.pack(fill=X, pady=6)
        ttk.Button(buttons, text="EXPORT INTEL", command=self.export_results).pack(fill=X)

        self.progress = ttk.Progressbar(main, mode="determinate")
        self.progress.pack(fill=X, pady=(12, 10))

        metrics = ttk.Frame(main)
        metrics.pack(fill=X, pady=(0, 10))
        self.hosts_metric = self._metric(metrics, "ASSETS", "0")
        self.ports_metric = self._metric(metrics, "SERVICES", "0")
        self.risk_metric = self._metric(metrics, "HIGH RISK", "0")
        self.status_var = tk.StringVar(value="DeepProbe standing by")
        ttk.Label(metrics, textvariable=self.status_var).pack(side=LEFT, padx=20)

        panes = ttk.Panedwindow(main, orient=tk.HORIZONTAL)
        panes.pack(fill=BOTH, expand=True)

        table_frame = ttk.Frame(panes)
        panes.add(table_frame, weight=3)

        columns = ("ip", "hostname", "alive", "latency", "os", "ports", "score", "risk")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "ip": "IP",
            "hostname": "Hostname",
            "alive": "Alive",
            "latency": "Latency",
            "os": "OS Guess",
            "ports": "Open Ports",
            "score": "Score",
            "risk": "Risk",
        }
        widths = {"ip": 125, "hostname": 180, "alive": 70, "latency": 90, "os": 150, "ports": 250, "score": 70, "risk": 90}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor=W)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)
        scrollbar = ttk.Scrollbar(table_frame, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        right_pane = ttk.Panedwindow(panes, orient=tk.VERTICAL)
        panes.add(right_pane, weight=2)

        graph_frame = ttk.Frame(right_pane)
        ttk.Label(graph_frame, text="LIVE TOPOLOGY", style="SubTitle.TLabel").pack(anchor=W)
        self.canvas = tk.Canvas(graph_frame, background="#061114", highlightthickness=1, highlightbackground="#1ddf99")
        self.canvas.pack(fill=BOTH, expand=True, pady=(6, 0))
        right_pane.add(graph_frame, weight=2)

        details_frame = ttk.Frame(right_pane)
        ttk.Label(details_frame, text="AI INTEL PANEL", style="SubTitle.TLabel").pack(anchor=W)
        self.details = tk.Text(details_frame, height=12, wrap="word", font=("Consolas", 10), bg="#061114", fg="#d7ffe8", insertbackground="#00ff9c")
        self._configure_text_tags(self.details)
        self.details.pack(fill=BOTH, expand=True, pady=(6, 0))
        right_pane.add(details_frame, weight=1)

        log_frame = ttk.Frame(main)
        log_frame.pack(fill=X, pady=(10, 0))
        ttk.Label(log_frame, text="OPS CONSOLE").pack(anchor=W)
        self.log = tk.Text(log_frame, height=5, wrap="word", font=("Consolas", 9), bg="#061114", fg="#00ff9c", insertbackground="#00ff9c")
        self.log.pack(fill=X)

    def _configure_text_tags(self, widget):
        widget.tag_configure("section", foreground="#00ff9c", font=("Consolas", 10, "bold"), spacing1=8)
        widget.tag_configure("critical", foreground="#ff4d4d", font=("Consolas", 10, "bold"))
        widget.tag_configure("high", foreground="#ff7a59", font=("Consolas", 10, "bold"))
        widget.tag_configure("medium", foreground="#ffcf5c", font=("Consolas", 10, "bold"))
        widget.tag_configure("low", foreground="#54f2a8")
        widget.tag_configure("label", foreground="#8fb9a8", font=("Consolas", 10, "bold"))
        widget.tag_configure("attack", foreground="#ffcf5c")
        widget.tag_configure("defense", foreground="#7dd3fc")
        widget.tag_configure("muted", foreground="#8fb9a8")

    def _render_details(self, lines):
        self.details.delete("1.0", END)
        for text, tag in lines:
            start = self.details.index(END)
            self.details.insert(END, text + "\n")
            end = self.details.index(END)
            if tag:
                self.details.tag_add(tag, start, end)
            lower = text.lower()
            if "[critical]" in lower or "critical " in lower:
                self.details.tag_add("critical", start, end)
            elif "[high]" in lower or "high " in lower:
                self.details.tag_add("high", start, end)
            elif "[medium]" in lower or "medium " in lower:
                self.details.tag_add("medium", start, end)

    def _tick_clock(self):
        self.clock_var.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _metric(self, parent, title, value):
        frame = ttk.Frame(parent, padding=(0, 0, 24, 0))
        frame.pack(side=LEFT)
        var = tk.StringVar(value=value)
        ttk.Label(frame, text=title).pack(anchor=W)
        ttk.Label(frame, textvariable=var, style="Metric.TLabel").pack(anchor=W)
        return var

    def _default_target(self):
        try:
            host = socket.gethostbyname(socket.gethostname())
            network = ipaddress.ip_network(f"{host}/24", strict=False)
            return str(network)
        except Exception:
            return "192.168.1.0/24"

    def start_scan(self):
        if not self.authorized_var.get():
            messagebox.showwarning(
                "Authorization required",
                "Confirm that you have permission to scan the selected targets before starting.",
            )
            return
        try:
            ports = parse_ports(self.ports_var.get())
            timeout = float(self.timeout_var.get())
            workers = int(self.workers_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid scan settings", str(exc))
            return

        self.results = []
        self.host_nodes = {}
        self.stop_event.clear()
        self.tree.delete(*self.tree.get_children())
        self.details.delete("1.0", END)
        self.canvas.delete("all")
        self.progress["value"] = 0
        self.status_var.set("Deep scan running...")
        self._update_metrics()
        self._log(f"DeepProbe started with profile '{self.ports_var.get()}' across {len(ports)} TCP port(s).")
        if self.udp_var.get():
            self._log("UDP-lite intelligence enabled for DNS/NTP/SNMP where selected.")
        if self.trace_var.get():
            self._log("Trace route enabled; scans may take longer.")

        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        scanner = NetworkScanner(self.events, self.stop_event)
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scanner, self.targets_var.get(), ports, timeout, workers),
            daemon=True,
        )
        self.scan_thread.start()

    def _run_scan(self, scanner, targets, ports, timeout, workers):
        try:
            results = scanner.scan(
                targets,
                ports,
                self.scan_dead_var.get(),
                timeout,
                workers,
                self.udp_var.get(),
                self.trace_var.get(),
                self.banner_var.get(),
            )
            self.events.put(("done", results))
        except ScanCancelled:
            self.events.put(("cancelled",))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")
        self._log("Stop requested.")

    def _drain_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self._log(event[1])
                elif kind == "progress":
                    self._set_progress(event[1], event[2])
                elif kind == "host":
                    self._add_host(event[1])
                elif kind == "done":
                    self.results = event[1]
                    self._finish_scan(f"Finished. Found {len(self.results)} host(s).")
                elif kind == "cancelled":
                    self._finish_scan("Scan cancelled.")
                elif kind == "error":
                    self._finish_scan("Scan failed.")
                    messagebox.showerror("Scan failed", event[1])
        except queue.Empty:
            pass
        self.after(120, self._drain_events)

    def _set_progress(self, done, total):
        self.progress["maximum"] = total
        self.progress["value"] = done
        self.status_var.set(f"Scanned {done}/{total} target(s)")

    def _add_host(self, host):
        self.results.append(host)
        ports = ", ".join(str(item.port) for item in host.ports)
        if host.udp_findings:
            udp_ports = ", ".join(f"{item.port}/u" for item in host.udp_findings)
            ports = f"{ports}, {udp_ports}" if ports else udp_ports
        self.tree.insert(
            "",
            END,
            iid=host.ip,
            values=(
                host.ip,
                host.hostname,
                "Yes" if host.alive else "No",
                f"{host.latency_ms:.0f} ms" if host.latency_ms else "",
                host.os_guess,
                ports,
                host.risk_score,
                host.risk_label,
            ),
        )
        self._update_metrics()
        self._draw_topology()

    def _finish_scan(self, message):
        self.status_var.set(message)
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self._update_metrics()
        self._draw_topology()
        self._log(message)

    def _update_metrics(self):
        self.hosts_metric.set(str(len(self.results)))
        self.ports_metric.set(str(sum(len(host.ports) + len(host.udp_findings) for host in self.results)))
        self.risk_metric.set(str(sum(1 for host in self.results if host.risk_label == "High")))

    def show_details(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        ip = selected[0]
        host = next((item for item in self.results if item.ip == ip), None)
        if not host:
            return
        lines = [
            ("TARGET INTEL", "section"),
            (f"IP: {host.ip}", "label"),
            (f"Hostname: {host.hostname or '-'}", "label"),
            (f"Alive: {'yes' if host.alive else 'no'}", "label"),
            (f"Latency: {host.latency_ms:.0f} ms" if host.latency_ms else "Latency: -", "label"),
            (f"OS guess: {host.os_guess}", "label"),
            (f"MAC: {host.mac or '-'}", "label"),
            (f"TTL hint: {host.ttl_hint or '-'}", "label"),
            (f"Risk: {host.risk_label} ({host.risk_score}/100)", host.risk_label.lower()),
            ("", None),
            (host.intelligence, "muted"),
            ("", None),
            ("OPEN TCP SERVICES - VULNERABILITY AND ATTACK ANALYSIS", "section"),
        ]
        if host.ports:
            for item in host.ports:
                lines.append((f"  {item.port}/tcp  {item.service:<14} {item.description}  [{item.severity.upper()}]", item.severity))
                lines.append((f"    Service purpose: {describe_service(item.port, item.service, item.description)}", "muted"))
                if item.banner:
                    lines.append((f"    Banner: {item.banner}", "muted"))
                if item.evidence:
                    lines.append((f"    Evidence: {item.evidence}", "muted"))
                if item.risk:
                    lines.append((f"    Risk signal: {item.risk}", item.severity))
                for analysis_line in format_port_attack_analysis(item):
                    tag = "attack" if analysis_line.startswith(("Weakness:", "Possible attack:", "Impact:")) else "defense"
                    lines.append((f"    {analysis_line}", tag))
                lines.append(("", None))
        else:
            lines.append(("  none found", "muted"))
        lines.append(("", None))
        lines.append(("UDP FINDINGS - INFRASTRUCTURE EXPOSURE", "section"))
        if host.udp_findings:
            for item in host.udp_findings:
                lines.append((f"  {item.port}/udp  {item.service:<14} {item.evidence or item.description}  [{item.severity.upper()}]", item.severity))
                lines.append((f"    Service purpose: {describe_service(item.port, item.service, item.description)}", "muted"))
                if item.banner:
                    lines.append((f"    Response hex: {item.banner}", "muted"))
                for analysis_line in format_port_attack_analysis(item):
                    tag = "attack" if analysis_line.startswith(("Weakness:", "Possible attack:", "Impact:")) else "defense"
                    lines.append((f"    {analysis_line}", tag))
                lines.append(("", None))
        else:
            lines.append(("  none found", "muted"))
        lines.append(("", None))
        lines.append(("FINGERPRINTS", "section"))
        if host.fingerprints:
            lines.extend((f"  - {item}", "muted") for item in host.fingerprints)
        else:
            lines.append(("  - none", "muted"))
        lines.append(("", None))
        lines.append(("WEAKNESSES", "section"))
        if host.findings:
            lines.extend((f"  - {item}", "attack") for item in host.findings)
        else:
            lines.append(("  - none", "muted"))
        lines.append(("", None))
        lines.append(("AI SECURITY RECOMMENDATIONS", "section"))
        if host.recommendations:
            lines.extend((f"  - {item}", "defense") for item in host.recommendations)
        else:
            lines.append(("  - none", "muted"))
        if host.trace:
            lines.append(("", None))
            lines.append(("TRACE ROUTE", "section"))
            lines.extend((f"  {idx}. {hop}", "muted") for idx, hop in enumerate(host.trace, start=1))
        self._render_details(lines)

    def _draw_topology(self):
        self.canvas.delete("all")
        width = max(self.canvas.winfo_width(), 500)
        height = max(self.canvas.winfo_height(), 280)
        center_x = width // 2
        center_y = height // 2
        for offset in range(80, min(width, height) // 2, 80):
            self.canvas.create_oval(center_x - offset, center_y - offset, center_x + offset, center_y + offset, outline="#0d2e32")
        self.canvas.create_oval(center_x - 52, center_y - 52, center_x + 52, center_y + 52, fill="#10262b", outline="#00ff9c", width=2)
        self.canvas.create_text(center_x, center_y - 6, text="DEEPPROBE", fill="#00ff9c", font=("Consolas", 10, "bold"))
        self.canvas.create_text(center_x, center_y + 12, text="CORE", fill="#8fb9a8", font=("Consolas", 8))
        if not self.results:
            self.canvas.create_text(center_x, center_y + 86, text="awaiting authorized probe", fill="#8fb9a8", font=("Consolas", 10))
            return

        radius = min(width, height) * 0.36
        count = len(self.results)
        for index, host in enumerate(self.results):
            angle = (2 * math.pi * index / max(count, 1)) - (math.pi / 2)
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            color = {"High": "#ff3b3b", "Medium": "#ffb020", "Low": "#00ff9c", "None": "#8fb9a8"}[host.risk_label]
            self.canvas.create_line(center_x, center_y, x, y, fill="#1b4248", width=2)
            self.canvas.create_oval(x - 31, y - 31, x + 31, y + 31, fill="#071013", outline=color, width=3)
            self.canvas.create_text(x, y - 4, text=str(len(host.ports) + len(host.udp_findings)), fill=color, font=("Consolas", 13, "bold"))
            self.canvas.create_text(x, y + 12, text=host.risk_label.upper(), fill="#d7ffe8", font=("Consolas", 7))
            label = host.hostname or host.ip
            if len(label) > 20:
                label = label[:17] + "..."
            self.canvas.create_text(x, y + 46, text=label, fill="#d7ffe8", font=("Consolas", 9))

    def export_results(self):
        if not self.results:
            messagebox.showinfo("No results", "Run a scan before exporting.")
            return
        folder = filedialog.askdirectory(title="Choose export folder")
        if not folder:
            return
        export_dir = Path(folder)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        json_path = export_dir / f"deepprobe-intel-{timestamp}.json"
        csv_path = export_dir / f"deepprobe-intel-{timestamp}.csv"
        html_path = export_dir / f"deepprobe-intel-{timestamp}.html"

        data = []
        for host in self.results:
            item = asdict(host)
            item["risk_score"] = host.risk_score
            item["risk_label"] = host.risk_label
            data.append(item)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow([
                "ip",
                "hostname",
                "alive",
                "latency_ms",
                "os_guess",
                "mac",
                "risk",
                "score",
                "tcp_ports",
                "udp_ports",
                "service_descriptions",
                "weaknesses",
                "port_attack_analysis",
                "security_recommendations",
                "ai_intel",
            ])
            for host in self.results:
                port_attack_analysis = []
                service_descriptions = []
                for port in host.ports + host.udp_findings:
                    heading = f"{port.port}/{port.protocol}/{port.service} [{port.severity.upper()}]"
                    service_descriptions.append(
                        f"{port.port}/{port.protocol}/{port.service}: {describe_service(port.port, port.service, port.description)}"
                    )
                    port_attack_analysis.append(heading + " - " + " ".join(format_port_attack_analysis(port)))
                writer.writerow([
                    host.ip,
                    host.hostname,
                    host.alive,
                    f"{host.latency_ms:.0f}",
                    host.os_guess,
                    host.mac,
                    host.risk_label,
                    host.risk_score,
                    " ".join(f"{port.port}/{port.service}" for port in host.ports),
                    " ".join(f"{port.port}/{port.service}" for port in host.udp_findings),
                    " | ".join(service_descriptions),
                    " | ".join(host.findings),
                    " | ".join(port_attack_analysis),
                    " | ".join(host.recommendations),
                    host.intelligence,
                ])

        html_path.write_text(self._build_html_report(data), encoding="utf-8")
        messagebox.showinfo("Export complete", f"Saved JSON, CSV, and HTML reports to:\n{export_dir}")

    def _build_html_report(self, data):
        rows = []
        for host in data:
            port_cards = []
            for item in host["ports"] + host["udp_findings"]:
                profile = get_port_attack_profile(item)
                recommendation = PORT_RECOMMENDATIONS.get(
                    item["port"],
                    "Validate business need, patch level, authentication, logging, and source-network restrictions.",
                )
                severity = html.escape(item["severity"].upper())
                port_cards.append(
                    "<div class='port-card'>"
                    f"<div><span class='badge {html.escape(item['severity'])}'>{severity}</span> "
                    f"<strong>{item['port']}/{html.escape(item['protocol'])}</strong> {html.escape(item['service'])}</div>"
                    f"<div><b>Service:</b> {html.escape(describe_service(item['port'], item['service'], item['description']))}</div>"
                    f"<div><b>Weakness:</b> {html.escape(profile['weakness'])}</div>"
                    f"<div><b>Possible attack:</b> {html.escape(profile['attack'])}</div>"
                    f"<div><b>Impact:</b> {html.escape(profile['impact'])}</div>"
                    f"<div><b>Defense:</b> {html.escape(recommendation)}</div>"
                    "</div>"
                )
            ports = "".join(port_cards) or "-"
            findings = "<br>".join(html.escape(item) for item in host["findings"]) or "-"
            recommendations = "<br>".join(html.escape(item) for item in host["recommendations"]) or "-"
            rows.append(
                "<tr>"
                f"<td>{html.escape(host['ip'])}</td>"
                f"<td>{html.escape(host['hostname'] or '-')}</td>"
                f"<td>{html.escape(host['os_guess'])}</td>"
                f"<td>{host['risk_label']} ({host['risk_score']})</td>"
                f"<td>{ports}</td>"
                f"<td>{findings}</td>"
                f"<td>{recommendations}</td>"
                "</tr>"
            )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DeepProbe Intelligence Report</title>
  <style>
    body {{ font-family: Consolas, Segoe UI, Arial, sans-serif; margin: 32px; color: #d7ffe8; background: #071013; }}
    h1 {{ color: #00ff9c; letter-spacing: 2px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #1d3d42; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #10262b; color: #00ff9c; }}
    .port-card {{ border: 1px solid #1d3d42; background: #0b1a1d; margin: 0 0 10px; padding: 10px; border-radius: 6px; }}
    .badge {{ display: inline-block; min-width: 72px; text-align: center; padding: 2px 6px; border-radius: 4px; color: #071013; font-weight: 700; }}
    .critical {{ background: #ff4d4d; }}
    .high {{ background: #ff7a59; }}
    .medium {{ background: #ffcf5c; }}
    .info, .low {{ background: #54f2a8; }}
    b {{ color: #8fb9a8; }}
  </style>
</head>
<body>
  <h1>DEEPPROBE INTELLIGENCE REPORT</h1>
  <p>Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
  <table>
    <thead><tr><th>IP</th><th>Hostname</th><th>OS Guess</th><th>Risk</th><th>Services</th><th>Weaknesses</th><th>AI Security Recommendations</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>"""

    def _log(self, message):
        self.log.insert(END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log.see(END)


def main():
    app = NetworkMapperApp()
    app.mainloop()


if __name__ == "__main__":
    main()
