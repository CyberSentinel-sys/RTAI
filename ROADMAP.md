# RTAI Product Roadmap

> **Vision:** The world's first fully autonomous, air-gapped Purple Team platform — deployable on any network, with or without internet access, from SMB to regulated enterprise.

---

## Month 1 — Air-Gapped Core ✅ Complete

The foundational offline-capable swarm engine.

| Deliverable | Status |
|---|---|
| Multi-agent swarm pipeline (Scout → Analyst → Strategist → Fixer → Report) | ✅ |
| Local LLM support via Ollama (llama3, mistral, codellama) | ✅ |
| Air-gapped SQLite CVE database with Dynamic Risk Scoring | ✅ |
| HunterAgent — memory-resident C2 beacon & shellcode detection | ✅ |
| Scapy ARP + ICMP host discovery (no nmap dependency for recon) | ✅ |
| Deterministic report assembly (structured Python + LLM prose only) | ✅ |
| Telegram approval-gate notifications | ✅ |
| Safety Filter — blocks disruptive remediation before operator approval | ✅ |
| Human-in-the-loop Approval Gate | ✅ |
| Streamlit CISO Dashboard | ✅ |

---

## Month 2 — Enterprise Integrations 🚧 In Progress

Licensing paywall, enterprise workflow integrations, and the DMZ CVE pipeline.

| Deliverable | Status |
|---|---|
| **License Engine** — HMAC-SHA256 signed tokens, Community vs Enterprise feature gating | ✅ |
| **Jira Cloud / Server integration** — ADF ticket auto-creation for top CVE findings | ✅ |
| **Ansible playbook generation** — structured YAML remediation alongside Bash scripts | ✅ |
| **DMZ Relay Server** — FastAPI CVE delta feed for air-gapped node sync | ✅ |
| **DevSecOps pre-push hook** — secrets scanner + forbidden file + lint gate | ✅ |
| `.env.example` enterprise variable documentation (Jira, Telegram, Relay) | ✅ |
| `scripts/sync_relay.py` — incremental delta sync client with dry-run mode | ✅ |
| `scripts/generate_license.py` — vendor-side license token CLI | ✅ |
| Multi-format remediation output (`REMEDIATION_FORMAT=bash\|ansible`) | ✅ |
| Jira section auto-appended to engagement report | ✅ |

---

## Month 3 — Compliance, Multi-Tenancy & SaaS Dashboard 🔜 Planned

Enterprise-grade compliance mapping and a hosted operator console.

| Deliverable | Status |
|---|---|
| **Compliance Engine** — automated HIPAA / SOC 2 control mapping per CVE finding | 🔜 |
| **Multi-Tenancy** — isolated per-client engagement namespaces with RBAC | 🔜 |
| **SaaS Dashboard** — hosted operator console with SSO (SAML / OIDC) | 🔜 |
| **Scheduled Engagements** — cron-driven recurring scans with delta reporting | 🔜 |
| **Evidence Package Export** — ZIP bundle (report + scripts + Ansible + evidence logs) for auditors | 🔜 |
| **Compliance Report Template** — pre-formatted HIPAA / SOC 2 audit-ready output | 🔜 |
| **NVD Live Feed Integration** — optional internet-connected NVD API sync | 🔜 |
| **Webhook Notifications** — Slack, Microsoft Teams, PagerDuty approval-gate alerts | 🔜 |
| **API Server** — REST API for CI/CD pipeline integration (trigger scan, poll status, fetch report) | 🔜 |
| **Executive PDF Export** — branded PDF version of the Markdown engagement report | 🔜 |

---

## Guiding Principles

1. **Air-gap first.** Every feature must function 100% offline. Cloud integrations are additive, never required.
2. **No hallucinations.** Structured findings are built deterministically from typed state. The LLM writes narrative prose only.
3. **Human in the loop.** No remediation script executes without explicit operator approval. The Approval Gate is non-negotiable.
4. **Minimal blast radius.** The Safety Filter blocks any operation with service-disruption potential until reviewed and confirmed.
5. **Audit trail.** Every agent event is timestamped in `action_log`. Every engagement is a reproducible, versioned artifact.
