#!/usr/bin/env python3
"""
scripts/seed_local_cve.py
Populate the local SQLite CVE database with high-critical real-world CVEs.

Run from the project root:
    python scripts/seed_local_cve.py

The database is written to: data/local_cves.db
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on the path when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.local_cve_db import LocalCveDatabase  # noqa: E402

SEED_DATA = [
    # ── Log4Shell ─────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-44228",
        "description": (
            "Log4Shell: Apache Log4j2 JNDI lookup feature allows unauthenticated "
            "remote code execution via specially crafted log messages.  CVSS 10.0."
        ),
        "cvss_score": 10.0,
        "affected_product": "log4j",
    },
    # ── regreSSHion ────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2024-6387",
        "description": (
            "regreSSHion: race condition in OpenSSH sshd signal handler allows "
            "unauthenticated remote code execution as root on glibc-based Linux systems."
        ),
        "cvss_score": 8.1,
        "affected_product": "openssh",
    },
    # ── EternalBlue ───────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2017-0144",
        "description": (
            "EternalBlue: SMBv1 in Microsoft Windows allows unauthenticated RCE via "
            "specially crafted packets.  Exploited by WannaCry and NotPetya ransomware."
        ),
        "cvss_score": 8.1,
        "affected_product": "smb",
    },
    # ── BlueKeep ──────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2019-0708",
        "description": (
            "BlueKeep: unauthenticated RCE via RDP pre-authentication in Windows 7 / "
            "Server 2008.  Wormable — no user interaction required."
        ),
        "cvss_score": 9.8,
        "affected_product": "rdp",
    },
    # ── Heartbleed ────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2014-0160",
        "description": (
            "Heartbleed: malformed TLS heartbeat requests cause OpenSSL 1.0.1–1.0.1f "
            "to return up to 64 KB of heap memory, leaking private keys and credentials."
        ),
        "cvss_score": 7.5,
        "affected_product": "openssl",
    },
    # ── ProFTPD mod_copy ──────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2015-3306",
        "description": (
            "ProFTPD < 1.3.5b: the mod_copy module allows unauthenticated remote "
            "attackers to read and write arbitrary files via SITE CPFR/CPTO commands."
        ),
        "cvss_score": 10.0,
        "affected_product": "proftpd",
    },
    # ── Ghostcat (Apache Tomcat) ──────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-1938",
        "description": (
            "Ghostcat: AJP connector in Apache Tomcat < 9.0.31 allows unauthenticated "
            "attackers to read arbitrary web app files and achieve RCE if file upload is possible."
        ),
        "cvss_score": 9.8,
        "affected_product": "tomcat",
    },
    # ── Redis Lua sandbox escape ───────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-0543",
        "description": (
            "Lua sandbox escape in Redis on Debian/Ubuntu: the Lua 'package' global "
            "is not removed, allowing arbitrary OS command execution."
        ),
        "cvss_score": 10.0,
        "affected_product": "redis",
    },
    # ── Apache HTTP Server path traversal + RCE ───────────────────────────────
    {
        "cve_id": "CVE-2021-42013",
        "description": (
            "Path traversal and RCE in Apache HTTP Server 2.4.49–2.4.50: URL-encoded "
            "path traversal bypasses access controls; mod_cgi enables remote code execution."
        ),
        "cvss_score": 9.8,
        "affected_product": "apache",
    },
    # ── vsftpd backdoor ───────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2011-2523",
        "description": (
            "vsftpd 2.3.4 backdoor: sending a username containing ':)' triggers a "
            "bind shell on port 6200/tcp, granting unauthenticated remote code execution."
        ),
        "cvss_score": 9.8,
        "affected_product": "vsftpd",
    },
    # ── Log4j second variant (CVE-2021-45046) ────────────────────────────────
    {
        "cve_id": "CVE-2021-45046",
        "description": (
            "Apache Log4j2 2.15.0 Context Lookup pattern allows crafted input to cause "
            "a denial of service or remote code execution in certain non-default configurations."
        ),
        "cvss_score": 9.0,
        "affected_product": "log4j",
    },
    # ── Samba vfs_fruit heap overflow ─────────────────────────────────────────
    {
        "cve_id": "CVE-2021-44142",
        "description": (
            "Heap-based buffer overflow in Samba vfs_fruit module < 4.13.17 allows an "
            "authenticated attacker with write access to execute arbitrary code as root."
        ),
        "cvss_score": 9.9,
        "affected_product": "samba",
    },
    # ── OpenSSH agent PKCS#11 RCE ─────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-38408",
        "description": (
            "ssh-agent in OpenSSH < 9.3p2 can be induced to load arbitrary libraries "
            "via PKCS#11 providers, enabling remote code execution."
        ),
        "cvss_score": 9.8,
        "affected_product": "openssh",
    },
    # ── MySQL config file RCE ─────────────────────────────────────────────────
    {
        "cve_id": "CVE-2016-6662",
        "description": (
            "MySQL < 5.7.15 allows authenticated users (sometimes unauthenticated via "
            "SQL injection) to create malicious my.cnf files, leading to RCE as root."
        ),
        "cvss_score": 9.8,
        "affected_product": "mysql",
    },
    # ── nginx DNS off-by-one ──────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-23017",
        "description": (
            "Off-by-one error in the nginx DNS resolver < 1.20.1 allows a remote attacker "
            "spoofing DNS responses to cause a 1-byte heap overwrite and potential RCE."
        ),
        "cvss_score": 9.4,
        "affected_product": "nginx",
    },
]


def main() -> None:
    db = LocalCveDatabase()
    before = db.count()
    db.insert_many(SEED_DATA)
    after = db.count()
    db.close()
    print(f"[+] Seeded {after - before} new CVE records into {db.db_path}")
    print(f"[+] Total records in database: {after}")


if __name__ == "__main__":
    main()
