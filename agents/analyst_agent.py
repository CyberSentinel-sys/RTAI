"""
agents/analyst_agent.py

Analyst agent: cross-references Scout output against a CVE database,
computes a Dynamic Risk Score per entry point, and produces a ranked list
of Exploitable Entry Points ordered by critical impact.

Analysis pipeline
-----------------
1. **Port extraction**
   Reads ``tool_outputs["scout"]`` (new format) or falls back to
   ``tool_outputs["nmap"]`` / recon findings (legacy format).

2. **CVE lookup** (``CveDatabase``)
   Fuzzy-matches product name and version against a curated mock database
   of real published CVEs.  Designed for easy replacement: subclass
   ``CveDatabase`` and override ``lookup()`` to call the NVD API
   (https://services.nvd.nist.gov/rest/json/cves/2.0) or any other feed.

3. **Dynamic Risk Score**
   For each entry point:

       score = min(10.0, cvss_base × reachability_mult
                        + exploit_bonus
                        + auth_bypass_bonus)

   Where:
   - ``cvss_base``         — highest CVSS v3 score across matching CVEs
                             (3.0 heuristic when no CVE found)
   - ``reachability_mult`` — port-based exposure weight (see ``_REACHABILITY``)
   - ``exploit_bonus``     — +0.5 when a public exploit / PoC exists
   - ``auth_bypass_bonus`` — +1.0 for unauthenticated / auth-bypass exploits

4. **LLM enrichment**
   Top-10 scored entry points are sent to the LLM for tactical analyst
   notes and an overall attack-surface summary.

Output (``state.tool_outputs["analyst"]``)
------------------------------------------
{
  "target": "...",
  "total_entry_points": N,
  "critical_count": N,
  "high_count": N,
  "exploitable_count": N,
  "entry_points": [
    {
      "rank": 1,
      "ip": "...",
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "product": "OpenSSH",
      "version": "9.2p1",
      "os_context": "Linux 5.x",
      "risk_hint": "SSH – prime brute-force ...",
      "cves": [ { "cve_id": "...", "cvss_v3": 9.8, ... } ],
      "reachability_factor": 1.2,
      "dynamic_risk_score": 10.0,
      "severity": "Critical",
      "exploit_available": true,
      "analyst_notes": "..."
    }
  ],
  "analyst_summary": "..."
}
"""
from __future__ import annotations

import json
import re
from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.config import Config
from core.state import RTAIState


# ---------------------------------------------------------------------------
# CVE record schema
# ---------------------------------------------------------------------------

class CveRecord(TypedDict):
    cve_id: str
    cvss_v3: float
    severity: str           # "Critical" | "High" | "Medium" | "Low"
    description: str
    affected_versions: str  # human-readable range, e.g. "< 9.3p2"
    exploit_available: bool
    exploit_type: str       # "RCE" | "PrivEsc" | "InfoDisc" | "DoS" | "AuthBypass" | "Other"
    patch_available: bool
    reference: str          # NVD URL or advisory identifier


# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

# Port → reachability weight.  Higher = more internet-exposed / frequently targeted.
_REACHABILITY: dict[int, float] = {
    # Web services (directly internet-facing)
    80: 1.30,  443: 1.30,  8080: 1.25,  8443: 1.25,  8000: 1.20,
    # Remote access (frequently brute-forced / credential-sprayed)
    22: 1.20,  23: 1.25,  3389: 1.20,  5900: 1.15,  5985: 1.10,  5986: 1.10,
    # File transfer
    21: 1.15,  69: 1.10,
    # Databases exposed on the network
    3306: 1.10,  5432: 1.10,  1433: 1.15,  1521: 1.10,
    27017: 1.15,  6379: 1.20,  9200: 1.15,  5984: 1.10,
    # Directory / network services
    389: 1.10,  636: 1.05,  161: 1.05,  2181: 1.10,
    # Windows / SMB
    445: 1.20,  139: 1.10,  135: 1.10,
}

_EXPLOIT_BONUS: float = 0.5      # public exploit / PoC exists
_AUTH_BYPASS_BONUS: float = 1.0  # exploit requires no authentication
_NO_CVE_BASE: float = 3.0        # heuristic CVSS when no CVE is found


# ---------------------------------------------------------------------------
# CVE database
# ---------------------------------------------------------------------------

class CveDatabase:
    """
    CVE lookup engine backed by a curated mock dataset of real CVEs.

    Mock data covers the most commonly exploited services found in
    penetration testing engagements: OpenSSH, Apache httpd, nginx,
    vsftpd, ProFTPD, MySQL/MariaDB, PostgreSQL, Samba/SMB, Redis,
    OpenSSL, Tomcat, VNC, Elasticsearch, MongoDB, RDP, Telnet, SNMP.

    Upgrading to a live feed
    ------------------------
    Subclass ``CveDatabase`` and override ``lookup()``::

        class NvdCveDatabase(CveDatabase):
            def lookup(self, product: str, version: str) -> list[CveRecord]:
                # Call https://services.nvd.nist.gov/rest/json/cves/2.0
                # and map results to CveRecord TypedDicts.
                ...

    Version matching
    ----------------
    Versions are parsed into integer tuples.  OpenSSH "p"-level suffixes
    (e.g. "9.3p2") and single-letter build suffixes (e.g. "1.0.1g") are
    handled.  Unknown / empty versions are treated as *vulnerable* (safe-fail).
    """

    # Schema: (product_keywords, max_version_exclusive, CveRecord)
    # product_keywords — list of lowercase substrings; ANY match triggers lookup
    # max_version      — "9999" means the CVE applies to ALL known versions
    _MOCK_DB: list[tuple[list[str], str, CveRecord]] = [

        # ── OpenSSH ──────────────────────────────────────────────────────────
        (["openssh"], "9.8", {
            "cve_id": "CVE-2024-6387",
            "cvss_v3": 8.1,
            "severity": "High",
            "description": (
                "RegreSSHion: race condition in the OpenSSH server (sshd) signal "
                "handler allows unauthenticated RCE as root on glibc-based Linux."
            ),
            "affected_versions": "< 9.8p1",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        }),
        (["openssh"], "9.3", {
            "cve_id": "CVE-2023-38408",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "ssh-agent in OpenSSH before 9.3p2 can be induced to load arbitrary "
                "libraries via PKCS#11 providers, enabling remote code execution."
            ),
            "affected_versions": "< 9.3p2",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        }),
        (["openssh"], "8.8", {
            "cve_id": "CVE-2021-41617",
            "cvss_v3": 7.0,
            "severity": "High",
            "description": (
                "sshd in OpenSSH 6.2–8.7 does not initialize supplemental groups "
                "properly, allowing local privilege escalation via AuthorizedKeysCommand."
            ),
            "affected_versions": "6.2 – 8.7",
            "exploit_available": False,
            "exploit_type": "PrivEsc",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41617",
        }),
        (["openssh"], "7.2", {
            "cve_id": "CVE-2016-0777",
            "cvss_v3": 6.5,
            "severity": "Medium",
            "description": (
                "The experimental roaming feature in OpenSSH 5.4–7.1 leaks process "
                "memory to a malicious SSH server, potentially disclosing private keys."
            ),
            "affected_versions": "5.4 – 7.1",
            "exploit_available": False,
            "exploit_type": "InfoDisc",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-0777",
        }),

        # ── Apache HTTP Server ────────────────────────────────────────────────
        (["apache", "httpd", "apache http"], "2.4.51", {
            "cve_id": "CVE-2021-42013",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "Path traversal and RCE in Apache HTTP Server 2.4.49–2.4.50: "
                "URL-encoded path traversal bypasses access controls; mod_cgi enables RCE."
            ),
            "affected_versions": "2.4.49 – 2.4.50",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        }),
        (["apache", "httpd", "apache http"], "2.4.50", {
            "cve_id": "CVE-2021-41773",
            "cvss_v3": 7.5,
            "severity": "High",
            "description": (
                "Path traversal in Apache HTTP Server 2.4.49 allows an attacker to "
                "read files outside the configured document root via URL manipulation."
            ),
            "affected_versions": "2.4.49",
            "exploit_available": True,
            "exploit_type": "InfoDisc",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        }),
        (["apache", "httpd", "apache http"], "2.4.55", {
            "cve_id": "CVE-2022-31813",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "Apache HTTP Server ≤ 2.4.53: mod_proxy may strip X-Forwarded-* headers "
                "based on client Connection headers, bypassing IP-based authentication."
            ),
            "affected_versions": "≤ 2.4.53",
            "exploit_available": True,
            "exploit_type": "AuthBypass",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-31813",
        }),

        # ── nginx ─────────────────────────────────────────────────────────────
        (["nginx"], "1.20.1", {
            "cve_id": "CVE-2021-23017",
            "cvss_v3": 9.4,
            "severity": "Critical",
            "description": (
                "Off-by-one error in the nginx DNS resolver before 1.20.1 allows a "
                "remote attacker spoofing DNS responses to cause a 1-byte heap overwrite, "
                "potentially leading to arbitrary code execution."
            ),
            "affected_versions": "< 1.20.1",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        }),
        (["nginx"], "1.13.3", {
            "cve_id": "CVE-2017-7529",
            "cvss_v3": 7.5,
            "severity": "High",
            "description": (
                "Integer overflow in the nginx range filter module (0.9.1 – 1.13.1) "
                "allows a remote attacker to disclose process memory via crafted "
                "byte-range requests."
            ),
            "affected_versions": "0.9.1 – 1.13.1",
            "exploit_available": False,
            "exploit_type": "InfoDisc",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-7529",
        }),

        # ── vsftpd ────────────────────────────────────────────────────────────
        (["vsftpd"], "2.3.5", {
            "cve_id": "CVE-2011-2523",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "vsftpd 2.3.4 contains a backdoor: sending a username containing ':)' "
                "triggers a bind shell on port 6200/tcp, granting unauthenticated RCE."
            ),
            "affected_versions": "2.3.4 only",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        }),

        # ── ProFTPD ───────────────────────────────────────────────────────────
        (["proftpd"], "1.3.5", {
            "cve_id": "CVE-2015-3306",
            "cvss_v3": 10.0,
            "severity": "Critical",
            "description": (
                "ProFTPD < 1.3.5b: the mod_copy module allows unauthenticated remote "
                "attackers to read and write arbitrary files via SITE CPFR/CPTO commands."
            ),
            "affected_versions": "< 1.3.5b",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
        }),

        # ── MySQL / MariaDB ───────────────────────────────────────────────────
        (["mysql", "mariadb"], "5.7.15", {
            "cve_id": "CVE-2016-6662",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "MySQL < 5.7.15 allows remote authenticated users (and sometimes "
                "unauthenticated via injection) to create malicious config files "
                "loaded by mysqld_safe, leading to RCE as root."
            ),
            "affected_versions": "< 5.7.15",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662",
        }),
        (["mysql", "mariadb"], "5.6.99", {
            "cve_id": "CVE-2012-2122",
            "cvss_v3": 7.5,
            "severity": "High",
            "description": (
                "Authentication bypass in MySQL 5.1–5.5.22: repeatedly submitting "
                "an incorrect password exploits a memcmp timing flaw to gain access "
                "without valid credentials."
            ),
            "affected_versions": "5.1 – 5.5.22",
            "exploit_available": True,
            "exploit_type": "AuthBypass",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122",
        }),

        # ── PostgreSQL ────────────────────────────────────────────────────────
        (["postgresql", "postgres"], "11.3", {
            "cve_id": "CVE-2019-9193",
            "cvss_v3": 8.8,
            "severity": "High",
            "description": (
                "PostgreSQL 9.3–11.2 allows authenticated superusers to execute "
                "arbitrary OS commands via COPY TO/FROM PROGRAM, leading to full "
                "system compromise."
            ),
            "affected_versions": "9.3 – 11.2",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-9193",
        }),
        (["postgresql", "postgres"], "16.1", {
            "cve_id": "CVE-2023-5869",
            "cvss_v3": 8.8,
            "severity": "High",
            "description": (
                "Heap buffer overflow in PostgreSQL < 16.1: certain operations on "
                "large composite values can lead to memory corruption and code execution."
            ),
            "affected_versions": "< 16.1",
            "exploit_available": False,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-5869",
        }),

        # ── Samba / SMB ───────────────────────────────────────────────────────
        (["samba", "smb", "netbios"], "4.13.17", {
            "cve_id": "CVE-2021-44142",
            "cvss_v3": 9.9,
            "severity": "Critical",
            "description": (
                "Heap-based buffer overflow in the vfs_fruit module of Samba < 4.13.17 "
                "allows an authenticated attacker with write access to a share to "
                "execute arbitrary code as root."
            ),
            "affected_versions": "< 4.13.17",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44142",
        }),
        (["samba", "smb", "netbios", "microsoft-ds"], "9999", {
            "cve_id": "CVE-2017-0144",
            "cvss_v3": 8.1,
            "severity": "High",
            "description": (
                "EternalBlue: SMBv1 in Microsoft Windows allows unauthenticated RCE "
                "via specially crafted packets.  Exploited by WannaCry and NotPetya."
            ),
            "affected_versions": "Windows with SMBv1 enabled",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        }),

        # ── Redis ─────────────────────────────────────────────────────────────
        (["redis"], "7.0.99", {
            "cve_id": "CVE-2022-0543",
            "cvss_v3": 10.0,
            "severity": "Critical",
            "description": (
                "Lua sandbox escape in Redis on Debian/Ubuntu: the Lua 'package' global "
                "is not removed, allowing arbitrary code execution on the host OS."
            ),
            "affected_versions": "Debian/Ubuntu Redis packages (multiple versions)",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
        }),
        (["redis"], "6.2.6", {
            "cve_id": "CVE-2021-32762",
            "cvss_v3": 8.8,
            "severity": "High",
            "description": (
                "Heap overflow in Redis < 6.2.6 RESP3 protocol handling; an attacker "
                "with access to the server can trigger memory corruption and execute code."
            ),
            "affected_versions": "< 6.2.6",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-32762",
        }),

        # ── OpenSSL ───────────────────────────────────────────────────────────
        (["openssl"], "1.0.1g", {
            "cve_id": "CVE-2014-0160",
            "cvss_v3": 7.5,
            "severity": "High",
            "description": (
                "Heartbleed: malformed TLS heartbeat requests cause OpenSSH 1.0.1–1.0.1f "
                "to return up to 64 KB of heap memory per request, leaking private keys, "
                "session tokens, and credentials."
            ),
            "affected_versions": "1.0.1 – 1.0.1f",
            "exploit_available": True,
            "exploit_type": "InfoDisc",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        }),
        (["openssl"], "3.0.2", {
            "cve_id": "CVE-2022-0778",
            "cvss_v3": 7.5,
            "severity": "High",
            "description": (
                "BN_mod_sqrt() in OpenSSL < 3.0.2 can loop infinitely for non-prime "
                "moduli, causing a denial-of-service when parsing attacker-supplied "
                "certificates in TLS clients and servers."
            ),
            "affected_versions": "< 3.0.2",
            "exploit_available": False,
            "exploit_type": "DoS",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
        }),

        # ── Apache Tomcat ─────────────────────────────────────────────────────
        (["tomcat", "apache tomcat"], "9.0.31", {
            "cve_id": "CVE-2020-1938",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "Ghostcat: the AJP connector in Apache Tomcat < 9.0.31 allows "
                "unauthenticated attackers to read arbitrary web application files; "
                "file inclusion enables RCE when file upload is possible."
            ),
            "affected_versions": "< 9.0.31",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
        }),

        # ── VNC ───────────────────────────────────────────────────────────────
        (["vnc", "libvncserver", "realvnc", "tigervnc", "ultravnc"], "0.9.13", {
            "cve_id": "CVE-2019-15694",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "Heap-based buffer overflow in LibVNCServer < 0.9.13: a malicious "
                "VNC server can exploit a NewFBSize message to execute arbitrary code "
                "on the client."
            ),
            "affected_versions": "< 0.9.13",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-15694",
        }),

        # ── Elasticsearch ─────────────────────────────────────────────────────
        (["elasticsearch"], "1.6.1", {
            "cve_id": "CVE-2015-1427",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "The Groovy scripting engine in Elasticsearch < 1.6.1 does not "
                "properly sandbox scripts, allowing remote code execution via "
                "crafted search queries."
            ),
            "affected_versions": "< 1.6.1",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427",
        }),

        # ── MongoDB ───────────────────────────────────────────────────────────
        (["mongodb"], "4.0.10", {
            "cve_id": "CVE-2019-2392",
            "cvss_v3": 6.5,
            "severity": "Medium",
            "description": (
                "Crafted queries in MongoDB < 4.0.10 can cause the server to crash, "
                "enabling denial-of-service by an authenticated user."
            ),
            "affected_versions": "< 4.0.10",
            "exploit_available": False,
            "exploit_type": "DoS",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-2392",
        }),

        # ── RDP ───────────────────────────────────────────────────────────────
        (["rdp", "ms-wbt-server", "remote desktop"], "9999", {
            "cve_id": "CVE-2019-0708",
            "cvss_v3": 9.8,
            "severity": "Critical",
            "description": (
                "BlueKeep: unauthenticated RCE via RDP in Windows 7 / Server 2008 R2 "
                "and earlier.  Wormable — no user interaction required."
            ),
            "affected_versions": "Windows 7 / Server 2008 R2 and earlier",
            "exploit_available": True,
            "exploit_type": "RCE",
            "patch_available": True,
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        }),

        # ── Telnet ────────────────────────────────────────────────────────────
        (["telnet"], "9999", {
            "cve_id": "MISC-TELNET-PLAINTEXT",
            "cvss_v3": 7.5,
            "severity": "High",
            "description": (
                "Telnet transmits all data—including credentials and commands—in "
                "plaintext.  Any attacker with network access can capture sessions "
                "via passive interception."
            ),
            "affected_versions": "All versions",
            "exploit_available": True,
            "exploit_type": "InfoDisc",
            "patch_available": False,
            "reference": "https://attack.mitre.org/techniques/T1040/",
        }),

        # ── SNMP ──────────────────────────────────────────────────────────────
        (["snmp"], "9999", {
            "cve_id": "MISC-SNMP-COMMUNITY",
            "cvss_v3": 7.3,
            "severity": "High",
            "description": (
                "SNMPv1/v2c community strings ('public', 'private') provide no "
                "cryptographic authentication.  An attacker with network access can "
                "enumerate the full MIB or reconfigure network devices."
            ),
            "affected_versions": "SNMPv1 and SNMPv2c (all versions)",
            "exploit_available": True,
            "exploit_type": "AuthBypass",
            "patch_available": False,
            "reference": "https://attack.mitre.org/techniques/T1602/002/",
        }),
    ]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def lookup(self, product: str, version: str) -> list[CveRecord]:
        """
        Return all CVE records applicable to *product* at *version*.

        Matching rules
        ~~~~~~~~~~~~~~
        - Product: case-insensitive substring match against any keyword.
        - Version: found version must be strictly less than ``max_version``
          (or ``max_version`` == "9999" meaning "all versions").
        - Unknown / empty versions are treated as vulnerable (conservative).
        - Results are deduplicated and sorted by CVSS score descending.

        Parameters
        ----------
        product : str
            Product or service name as reported by nmap.
        version : str
            Version string as reported by nmap (empty string if unknown).

        Returns
        -------
        List of ``CveRecord`` dicts, highest CVSS first.
        """
        norm = product.lower()
        matches: list[CveRecord] = []

        for keywords, max_ver, record in self._MOCK_DB:
            if not any(kw in norm for kw in keywords):
                continue
            if max_ver == "9999" or self._version_lt(version, max_ver):
                matches.append(record)

        # Deduplicate by CVE ID, preserve highest-CVSS ordering
        seen: set[str] = set()
        unique: list[CveRecord] = []
        for r in sorted(matches, key=lambda x: x["cvss_v3"], reverse=True):
            if r["cve_id"] not in seen:
                seen.add(r["cve_id"])
                unique.append(r)

        return unique

    # ------------------------------------------------------------------
    # Version comparison helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_version(v: str) -> tuple[int, ...]:
        """
        Convert a version string to a comparable integer tuple.

        Handles dotted semver, OpenSSH "p"-level suffixes (9.3p2 → 9.3.2),
        and single-letter build tags (1.0.1g → 1.0.1.7).
        Unknown strings return ``(0,)``.
        """
        if not v or v.strip() in ("", "unknown", "?", "-"):
            return (0,)
        # Normalise OpenSSH "p" suffix: "9.3p2" → "9.3.2"
        v = re.sub(r"p(\d+)", r".\1", v)
        # Normalise letter build suffix: "1.0.1g" → "1.0.1.7" (a=1, g=7)
        v = re.sub(r"([a-z])$", lambda m: f".{ord(m.group(1)) - 96}", v)
        parts = re.findall(r"\d+", v)
        return tuple(int(x) for x in parts) if parts else (0,)

    def _version_lt(self, found: str, max_ver: str) -> bool:
        """
        Return True if *found* version is strictly less than *max_ver*.
        Empty / unknown found versions are treated as vulnerable.
        """
        if not found or found.strip() in ("", "unknown", "?", "-"):
            return True
        a = self._parse_version(found)
        b = self._parse_version(max_ver)
        pad = max(len(a), len(b))
        a += (0,) * (pad - len(a))
        b += (0,) * (pad - len(b))
        return a < b


# ---------------------------------------------------------------------------
# Local SQLite CVE adapter
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


class LocalCveDbAdapter:
    """
    Wraps ``LocalCveDatabase`` and exposes a ``lookup()`` method that returns
    ``CveRecord``-compatible dicts so the rest of AnalystAgent is unchanged.

    Fields not stored in the SQLite schema (``exploit_available``,
    ``exploit_type``, ``patch_available``, ``reference``) are derived from
    the description text or set to conservative defaults.
    """

    def __init__(self) -> None:
        from core.local_cve_db import LocalCveDatabase
        self._db = LocalCveDatabase()

    def lookup(self, product: str, version: str) -> list[CveRecord]:  # noqa: ARG002
        rows = self._db.search_by_product(product)
        records: list[CveRecord] = []
        for row in rows:
            desc_lower = row["description"].lower()
            exploit_available = any(
                kw in desc_lower
                for kw in (
                    "rce", "remote code execution", "exploit", "backdoor",
                    "metasploit", "poc", "arbitrary code", "code execution",
                )
            )
            if "authbypass" in desc_lower or "auth bypass" in desc_lower:
                exploit_type = "AuthBypass"
            elif "privesc" in desc_lower or "privilege escalation" in desc_lower:
                exploit_type = "PrivEsc"
            elif "information disclosure" in desc_lower or "memory" in desc_lower or "leak" in desc_lower:
                exploit_type = "InfoDisc"
            elif "denial" in desc_lower or " dos" in desc_lower:
                exploit_type = "DoS"
            elif exploit_available:
                exploit_type = "RCE"
            else:
                exploit_type = "Other"

            cve_id = row["cve_id"]
            nvd_ref = (
                f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                if cve_id.startswith("CVE-")
                else "N/A"
            )

            records.append({
                "cve_id": cve_id,
                "cvss_v3": float(row["cvss_score"]),
                "severity": _cvss_to_severity(float(row["cvss_score"])),
                "description": row["description"],
                "affected_versions": row["affected_product"],
                "exploit_available": exploit_available,
                "exploit_type": exploit_type,
                "patch_available": True,
                "reference": nvd_ref,
            })
        return records


# ---------------------------------------------------------------------------
# Analyst agent
# ---------------------------------------------------------------------------

class AnalystAgent(BaseAgent):
    """
    Analyst agent: CVE cross-reference + Dynamic Risk Scoring.

    Reads ScoutAgent output (or legacy nmap data), queries the CVE database
    for each discovered service, computes Dynamic Risk Scores, and produces
    a ranked list of Exploitable Entry Points enriched with LLM tactical notes.

    Compatible with standalone usage and the ``SwarmController`` pipeline
    via ``BaseAgent.execute()``.
    """

    role = "Analyst"
    goal = (
        "Cross-reference discovered services against the CVE database. "
        "Compute a Dynamic Risk Score combining CVSS score and port reachability. "
        "Produce a ranked list of Exploitable Entry Points ordered by critical impact."
    )

    # Maximum number of entry points passed to the LLM (avoids token limits)
    _LLM_TOP_N: int = 10

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def run(self, state: RTAIState) -> dict[str, Any]:
        db: CveDatabase | LocalCveDbAdapter = (
            LocalCveDbAdapter() if Config.USE_LOCAL_OSINT else CveDatabase()
        )
        ports = self._extract_ports(state)

        # --- CVE lookup and scoring per entry point ----------------------
        entry_points: list[dict[str, Any]] = []
        for ip, port_info, os_context in ports:
            product = (port_info.get("product") or port_info.get("service") or "").strip()
            version = (port_info.get("version") or "").strip()
            port_num: int = port_info.get("port", 0)

            cves = db.lookup(product, version)
            score, severity = self._dynamic_risk_score(port_num, cves)

            entry_points.append({
                "rank": 0,          # assigned after sorting
                "ip": ip,
                "port": port_num,
                "protocol": port_info.get("protocol", "tcp"),
                "service": port_info.get("service", ""),
                "product": product,
                "version": version,
                "os_context": os_context,
                "risk_hint": port_info.get("risk_hint", ""),
                "cves": cves,
                "reachability_factor": round(_REACHABILITY.get(port_num, 1.0), 2),
                "dynamic_risk_score": score,
                "severity": severity,
                "exploit_available": any(c["exploit_available"] for c in cves),
                "analyst_notes": "",    # populated by LLM enrichment
            })

        # --- Sort by score desc, then exploit availability ---------------
        entry_points.sort(
            key=lambda x: (x["dynamic_risk_score"], x["exploit_available"]),
            reverse=True,
        )
        for i, ep in enumerate(entry_points, 1):
            ep["rank"] = i

        # --- LLM enrichment ----------------------------------------------
        analyst_summary = self._llm_enrich(state.target, entry_points)

        # --- Assemble final result ----------------------------------------
        result: dict[str, Any] = {
            "target": state.target,
            "total_entry_points": len(entry_points),
            "critical_count": sum(1 for e in entry_points if e["severity"] == "Critical"),
            "high_count": sum(1 for e in entry_points if e["severity"] == "High"),
            "medium_count": sum(1 for e in entry_points if e["severity"] == "Medium"),
            "exploitable_count": sum(1 for e in entry_points if e["exploit_available"]),
            "entry_points": entry_points,
            "analyst_summary": analyst_summary,
        }

        return {
            "tool_outputs": {"analyst": result},
            "findings": [
                {
                    "phase": "analyst",
                    "target": state.target,
                    "total_entry_points": result["total_entry_points"],
                    "critical_count": result["critical_count"],
                    "high_count": result["high_count"],
                    "exploitable_count": result["exploitable_count"],
                    "entry_points": entry_points,
                    "analyst_summary": analyst_summary,
                }
            ],
            "current_step": "analyst_complete",
        }

    # ------------------------------------------------------------------
    # Port extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_ports(
        state: RTAIState,
    ) -> list[tuple[str, dict[str, Any], str]]:
        """
        Return ``(ip, port_info_dict, os_context_str)`` tuples from state.

        Priority
        --------
        1. ``tool_outputs["scout"]``  — ScoutAgent structured format
           (keys: ``"open_ports"``, ``"ip"``, ``"os_guesses"``)
        2. ``tool_outputs["nmap"]``   — legacy ReconAgent format
           (keys: ``"ports"``, ``"host"``, ``"os_matches"``)
        3. ``findings[phase=recon]["nmap_raw"]`` — embedded raw nmap output
        """
        results: list[tuple[str, dict[str, Any], str]] = []

        # 1. Scout output (preferred)
        scout = state.tool_outputs.get("scout", {})
        if scout.get("hosts"):
            for host in scout["hosts"]:
                ip = host.get("ip", "")
                guesses = host.get("os_guesses", [])
                os_ctx = guesses[0]["name"] if guesses else ""
                for port_info in host.get("open_ports", []):
                    results.append((ip, port_info, os_ctx))
            return results

        # 2. Legacy nmap output
        nmap: dict[str, Any] = state.tool_outputs.get("nmap") or {}

        # 3. Embedded raw nmap from recon finding
        if not nmap.get("hosts"):
            nmap = next(
                (
                    f["nmap_raw"]
                    for f in state.findings
                    if f.get("phase") == "recon" and f.get("nmap_raw")
                ),
                {},
            )

        for host in nmap.get("hosts", []):
            ip = host.get("host") or host.get("ip", "")
            os_list = host.get("os_matches") or host.get("os_guesses") or []
            os_ctx = os_list[0]["name"] if os_list else ""
            for port_info in host.get("ports", []):
                results.append((ip, port_info, os_ctx))

        return results

    # ------------------------------------------------------------------
    # Dynamic Risk Score
    # ------------------------------------------------------------------

    @staticmethod
    def _dynamic_risk_score(
        port: int,
        cves: list[CveRecord],
    ) -> tuple[float, str]:
        """
        Compute a Dynamic Risk Score (0.0–10.0) and severity label.

        Formula
        -------
        ::

            score = min(10.0, cvss_base × reachability_mult
                              + exploit_bonus
                              + auth_bypass_bonus)

        When no CVEs are found a heuristic base of ``_NO_CVE_BASE`` is used
        so that any open port still receives a non-zero score.

        Parameters
        ----------
        port : int
            TCP/UDP port number.
        cves : list[CveRecord]
            CVE records already sorted CVSS descending (highest first).

        Returns
        -------
        ``(score, severity_label)``
        """
        reach = _REACHABILITY.get(port, 1.0)

        if not cves:
            score = min(10.0, _NO_CVE_BASE * reach)
        else:
            worst = cves[0]   # highest CVSS
            base = worst["cvss_v3"] * reach
            bonus: float = _EXPLOIT_BONUS if worst["exploit_available"] else 0.0
            if worst["exploit_type"] == "AuthBypass":
                bonus += _AUTH_BYPASS_BONUS
            score = min(10.0, base + bonus)

        score = round(score, 2)

        if score >= 9.0:
            label = "Critical"
        elif score >= 7.0:
            label = "High"
        elif score >= 4.0:
            label = "Medium"
        else:
            label = "Low"

        return score, label

    # ------------------------------------------------------------------
    # LLM enrichment
    # ------------------------------------------------------------------

    def _llm_enrich(
        self,
        target: str,
        entry_points: list[dict[str, Any]],
    ) -> str:
        """
        Send the top-N scored entry points to the LLM for tactical analyst
        commentary.  Populates ``entry_points[*]["analyst_notes"]`` in place
        and returns the overall analyst summary string.

        Falls back to raw LLM text if the JSON response cannot be parsed.
        """
        top = entry_points[: self._LLM_TOP_N]

        # Build a lean view for the LLM (exclude full CVE dicts to save tokens)
        condensed = [
            {
                "rank": ep["rank"],
                "ip": ep["ip"],
                "port": ep["port"],
                "service": f"{ep['product']} {ep['version']}".strip() or ep["service"],
                "severity": ep["severity"],
                "dynamic_risk_score": ep["dynamic_risk_score"],
                "reachability_factor": ep["reachability_factor"],
                "top_cves": [c["cve_id"] for c in ep["cves"][:3]],
                "exploit_available": ep["exploit_available"],
                "os_context": ep["os_context"],
            }
            for ep in top
        ]

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    f"Scored exploitable entry points (top {len(condensed)}, "
                    "highest Dynamic Risk Score first):\n"
                    f"```json\n{json.dumps(condensed, indent=2)}\n```\n\n"
                    "Return your response in this EXACT JSON format "
                    "(no markdown fences, no extra keys):\n"
                    "{\n"
                    '  "analyst_summary": "<3-5 sentence prioritised overview of '
                    'the attack surface and recommended exploitation order>",\n'
                    '  "entry_point_notes": [\n'
                    "    {\n"
                    '      "rank": <integer>,\n'
                    '      "tactical_note": "<1-2 sentence specific exploitation '
                    'tip, tool recommendation, or evasion consideration>"\n'
                    "    }\n"
                    "  ]\n"
                    "}"
                )
            ),
        ]

        try:
            response = self.llm.invoke(messages)
            parsed = json.loads(response.content)

            # Merge tactical notes back into entry_points list
            notes: dict[int, str] = {
                n["rank"]: n["tactical_note"]
                for n in parsed.get("entry_point_notes", [])
                if isinstance(n, dict)
            }
            for ep in entry_points:
                ep["analyst_notes"] = notes.get(ep["rank"], "")

            return parsed.get("analyst_summary", response.content)

        except (json.JSONDecodeError, AttributeError, KeyError):
            # LLM returned non-JSON — store raw content as summary
            raw = getattr(locals().get("response"), "content", "")
            return raw or "LLM enrichment produced no parseable output."
        except Exception as exc:  # noqa: BLE001
            return f"LLM enrichment unavailable: {exc}"
