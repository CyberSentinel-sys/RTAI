# Penetration Test Report

| Field | Value |
|---|---|
| **Engagement** | Sample_Lab_Assessment |
| **Target** | `192.0.2.10` |
| **Date** | 2026-01-15 |
| **Classification** | CONFIDENTIAL |

## Executive Summary

The penetration test of Sample_Lab_Assessment at 192.0.2.10 identified three high-risk vulnerabilities with active public exploits and two medium-risk findings. The most critical exposure is a remote code execution flaw in the Samba service (CVE-2017-7494), which has a public Metasploit module and poses an immediate risk of full system compromise. A full remediation plan with copy-paste shell commands is provided below. Re-testing is recommended after patches are applied.

## Scope & Methodology

- **Target scope:** `192.0.2.10`
- **Assessment date:** 2026-01-15
- **Methodology:** Automated pipeline — Reconnaissance (Nmap) → OSINT intelligence gathering (Tavily) → Exploitation analysis → Remediation planning → Report
- **Tools:** python-nmap, Tavily Search API, OpenAI LLM

## Reconnaissance

### Host: `192.0.2.10` (sample-host.local)

**State:** up

**OS Detection:**
- Linux 4.x (accuracy: 92%)

| Port | Protocol | Service | Product | Version |
|---|---|---|---|---|
| 22 | tcp | ssh | OpenSSH | 7.4 |
| 80 | tcp | http | Apache httpd | 2.4.49 |
| 139 | tcp | netbios-ssn | Samba smbd | 3.X - 4.X |
| 445 | tcp | netbios-ssn | Samba smbd | 3.X - 4.X |
| 3306 | tcp | mysql | MySQL | 5.7.38 |

### Recon Analysis

- **Open Ports and Services:**
  - **Port 22/tcp** — OpenSSH 7.4: potential for CVE-based SSH exploits
  - **Port 80/tcp** — Apache 2.4.49: known path traversal vulnerability
  - **Ports 139/445/tcp** — Samba: high-value SMB attack surface
  - **Port 3306/tcp** — MySQL exposed externally; potential for auth bypass

## OSINT Intelligence

**Services researched:** `OpenSSH 7.4`, `Apache httpd 2.4.49`, `Samba smbd 3.X - 4.X`, `MySQL 5.7.38`

### Top 3 High-Risk Findings

| Rank | Service | Type | Identifier | CVSS | Description | Source |
|---|---|---|---|---|---|---|
| 1 | Samba smbd 3.X - 4.X | CVE | `CVE-2017-7494` | 7.5 | Remote code execution via malicious shared library upload in writable share. | [link](https://nvd.nist.gov/vuln/detail/CVE-2017-7494) |
| 2 | Apache httpd 2.4.49 | CVE | `CVE-2021-41773` | 7.5 | Path traversal and RCE via crafted requests when mod_cgi is enabled. | [link](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) |
| 3 | MySQL 5.7.38 | DefaultCreds | `N/A` | N/A | MySQL root account accessible without password from external interface. | N/A |

### OSINT Analyst Summary

The OSINT phase identified critical vulnerabilities across three services. CVE-2017-7494 (SambaCry) and CVE-2021-41773 (Apache path traversal) both have public proof-of-concept exploits and Metasploit modules. The externally-exposed MySQL instance with default credentials presents an immediate data exfiltration risk. Immediate patching and network segmentation are required.

## Exploitation Analysis

1. **Samba smbd — SambaCry RCE**
   - **Affected Service / Port:** Samba smbd / Ports 139, 445
   - **CVE Identifier and CVSS Score:** CVE-2017-7494, CVSS 7.5
   - **Recommended Tooling:** Metasploit `exploit/linux/samba/is_known_pipename`
   - **risk_level:** High

2. **Apache httpd — Path Traversal / RCE**
   - **Affected Service / Port:** Apache httpd 2.4.49 / Port 80
   - **CVE Identifier and CVSS Score:** CVE-2021-41773, CVSS 7.5
   - **Recommended Tooling:** `curl 'http://192.0.2.10/cgi-bin/.%2e/.%2e/bin/sh'`
   - **risk_level:** High

3. **MySQL — Unauthenticated External Access**
   - **Affected Service / Port:** MySQL 5.7.38 / Port 3306
   - **CVE Identifier and CVSS Score:** N/A (misconfiguration)
   - **Recommended Tooling:** `mysql -h 192.0.2.10 -u root`
   - **risk_level:** High

4. **OpenSSH 7.4 — Username Enumeration**
   - **Affected Service / Port:** OpenSSH / Port 22
   - **CVE Identifier and CVSS Score:** CVE-2018-15473, CVSS 5.3
   - **Recommended Tooling:** `ssh-audit 192.0.2.10`
   - **risk_level:** Medium

5. **MySQL — Outdated Version**
   - **Affected Service / Port:** MySQL 5.7.38 / Port 3306
   - **CVE Identifier and CVSS Score:** Multiple CVEs in 5.7.x branch
   - **Recommended Tooling:** Version fingerprinting
   - **risk_level:** Medium

## Remediation Plan

| # | Title | Risk | Service | CVE |
|---|---|---|---|---|
| 1 | Patch Samba CVE-2017-7494 | **High** | Samba smbd 3.X - 4.X | `CVE-2017-7494` |
| 2 | Patch Apache CVE-2021-41773 | **High** | Apache httpd 2.4.49 | `CVE-2021-41773` |
| 3 | Secure MySQL External Access | **High** | MySQL 5.7.38 | `N/A` |
| 4 | Update OpenSSH | **Medium** | OpenSSH 7.4 | `CVE-2018-15473` |
| 5 | Upgrade MySQL to 8.x | **Medium** | MySQL 5.7.38 | `N/A` |

### 1. Patch Samba CVE-2017-7494

**Risk:** High &nbsp;|&nbsp; **Service:** Samba smbd 3.X - 4.X &nbsp;|&nbsp; **CVE:** `CVE-2017-7494`

**Steps:**
1. Stop the Samba service: `systemctl stop smbd`
2. Back up configuration: `cp /etc/samba/smb.conf /etc/samba/smb.conf.bak`
3. Update Samba: `apt-get update && apt-get install --only-upgrade samba`
4. Restart: `systemctl start smbd`

**Commands / Config:**
```bash
apt-get update && apt-get install --only-upgrade samba
systemctl restart smbd
```

**Verification:** `smbd -V | grep -E '4\.6\.5|4\.7|4\.8'`

### 2. Patch Apache CVE-2021-41773

**Risk:** High &nbsp;|&nbsp; **Service:** Apache httpd 2.4.49 &nbsp;|&nbsp; **CVE:** `CVE-2021-41773`

**Steps:**
1. Stop Apache: `systemctl stop apache2`
2. Upgrade: `apt-get update && apt-get install --only-upgrade apache2`
3. Restart: `systemctl start apache2`

**Commands / Config:**
```bash
apt-get update && apt-get install --only-upgrade apache2
```

**Verification:** `apache2 -v | grep 2.4.51`

### 3. Secure MySQL External Access

**Risk:** High &nbsp;|&nbsp; **Service:** MySQL 5.7.38 &nbsp;|&nbsp; **CVE:** `N/A`

**Steps:**
1. Bind MySQL to localhost only: edit `/etc/mysql/mysql.conf.d/mysqld.cnf`
2. Set `bind-address = 127.0.0.1`
3. Set a strong root password: `ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPass!';`
4. Restart: `systemctl restart mysql`

**Commands / Config:**
```bash
# /etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1
```

**Verification:** `nmap -p 3306 192.0.2.10 | grep 'closed\|filtered'`

### 4. Update OpenSSH

**Risk:** Medium &nbsp;|&nbsp; **Service:** OpenSSH 7.4 &nbsp;|&nbsp; **CVE:** `CVE-2018-15473`

**Steps:**
1. Update OpenSSH: `apt-get update && apt-get install --only-upgrade openssh-server`
2. Restart: `systemctl restart sshd`

**Commands / Config:**
```bash
apt-get update && apt-get install --only-upgrade openssh-server
```

**Verification:** `ssh -V`

### 5. Upgrade MySQL to 8.x

**Risk:** Medium &nbsp;|&nbsp; **Service:** MySQL 5.7.38 &nbsp;|&nbsp; **CVE:** `N/A`

**Steps:**
1. Back up all databases: `mysqldump --all-databases > all_dbs.sql`
2. Remove MySQL 5.7: `apt-get remove mysql-server`
3. Install MySQL 8: `apt-get install mysql-server`
4. Restore: `mysql < all_dbs.sql`

**Commands / Config:**
```bash
mysqldump --all-databases > all_dbs.sql
apt-get remove mysql-server && apt-get install mysql-server
```

**Verification:** `mysql --version | grep '8\.'`

## Conclusion

This engagement demonstrated that the target host carries significant exploitable risk, particularly via SambaCry and Apache path traversal — both of which have public, weaponised exploits. All five remediation steps should be applied before this host is considered production-ready. A follow-up assessment is recommended after patches are applied to confirm effective closure of each finding.
