"""
integrations/jira_client.py
Lightweight Jira Cloud / Server REST API client for RTAI.

Uses only the ``requests`` library — no Jira SDK dependency.

Supports Jira Cloud (Basic-auth with API token) and Jira Server/Data Center
(same auth scheme when Personal Access Tokens are used).

Usage
-----
    from integrations.jira_client import JiraEnterpriseClient

    client = JiraEnterpriseClient(
        server_url="https://your-org.atlassian.net",
        user_email="security@your-org.com",
        api_token="your-api-token",
        project_key="ITSEC",
    )
    url = client.create_remediation_ticket(
        cve_id="CVE-2024-6387",
        risk_score=9.8,
        description="OpenSSH regreSSHion RCE ...",
        remediation_code="apt-get install -y --only-upgrade openssh-server",
        fmt="bash",
    )
    print(url)   # https://your-org.atlassian.net/browse/ITSEC-42
"""
from __future__ import annotations

import json
import textwrap
from typing import Any

import requests
from requests.auth import HTTPBasicAuth


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _score_to_priority(score: float) -> str:
    """Map a CVSS / Dynamic Risk Score to a Jira priority name."""
    if score >= 9.0:
        return "Highest"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _score_to_severity_label(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class JiraEnterpriseClient:
    """
    Thin Jira REST API v3 wrapper for creating remediation tickets.

    Parameters
    ----------
    server_url:
        Base URL of the Jira instance, e.g. ``https://acme.atlassian.net``.
        Trailing slash is stripped automatically.
    user_email:
        Email address of the Jira account used for authentication.
    api_token:
        API token generated at id.atlassian.com (Cloud) or in Jira profile
        settings (Server / Data Center).
    project_key:
        Short project key, e.g. ``"ITSEC"``.  The issue will be created
        inside this project.
    issue_type:
        Jira issue type name.  Defaults to ``"Task"``; use ``"Bug"`` if
        your project workflow requires it.
    timeout:
        HTTP request timeout in seconds.
    """

    _API_PATH = "/rest/api/3/issue"

    def __init__(
        self,
        server_url: str,
        user_email: str,
        api_token: str,
        project_key: str = "ITSEC",
        issue_type: str = "Task",
        timeout: int = 15,
    ) -> None:
        self.base_url = server_url.rstrip("/")
        self.project_key = project_key
        self.issue_type = issue_type
        self.timeout = timeout
        self._auth = HTTPBasicAuth(user_email, api_token)
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_remediation_ticket(
        self,
        cve_id: str,
        risk_score: float,
        description: str,
        remediation_code: str,
        fmt: str = "bash",
        target: str = "",
        service: str = "",
    ) -> str:
        """
        Create a Jira issue for a security finding and return its browse URL.

        Parameters
        ----------
        cve_id:
            CVE identifier, e.g. ``"CVE-2024-6387"``.
        risk_score:
            Numeric Dynamic Risk Score (0–10) used to set Jira priority.
        description:
            Plain-text description of the vulnerability.
        remediation_code:
            Bash script or Ansible YAML to embed in the ticket body.
        fmt:
            ``"bash"`` or ``"ansible"`` — affects the code-block language tag.
        target:
            Target IP or hostname (informational, embedded in ticket).
        service:
            Affected service name (informational).

        Returns
        -------
        URL of the created Jira issue, e.g.
        ``"https://acme.atlassian.net/browse/ITSEC-42"``.

        Raises
        ------
        RuntimeError
            If the Jira API returns a non-2xx response.
        requests.exceptions.RequestException
            On network errors.
        """
        severity_label = _score_to_severity_label(risk_score)
        code_lang = "yaml" if fmt == "ansible" else "bash"

        summary = (
            f"[{severity_label}] Security Finding: {cve_id}"
            + (f" on {service}" if service else "")
            + (f" ({target})" if target else "")
        )
        # Jira Cloud uses Atlassian Document Format (ADF) for rich-text fields.
        # We use a simple paragraph + code-block ADF structure.
        adf_body = self._build_adf_body(
            cve_id=cve_id,
            risk_score=risk_score,
            severity_label=severity_label,
            description=description,
            remediation_code=remediation_code,
            code_lang=code_lang,
            target=target,
            service=service,
        )

        payload: dict[str, Any] = {
            "fields": {
                "project":   {"key": self.project_key},
                "summary":   summary,
                "issuetype": {"name": self.issue_type},
                "priority":  {"name": _score_to_priority(risk_score)},
                "description": adf_body,
                "labels": ["security", "rtai-auto", severity_label.lower()],
            }
        }

        url = self.base_url + self._API_PATH
        resp = requests.post(
            url,
            headers=self._headers,
            auth=self._auth,
            data=json.dumps(payload),
            timeout=self.timeout,
        )

        if not resp.ok:
            raise RuntimeError(
                f"Jira API error {resp.status_code}: {resp.text[:500]}"
            )

        issue_key = resp.json().get("key", "")
        return f"{self.base_url}/browse/{issue_key}"

    def health_check(self) -> bool:
        """
        Return True if the Jira instance is reachable and credentials are valid.

        Hits ``/rest/api/3/myself`` — a lightweight endpoint that returns
        the authenticated user's profile.
        """
        try:
            resp = requests.get(
                self.base_url + "/rest/api/3/myself",
                headers=self._headers,
                auth=self._auth,
                timeout=self.timeout,
            )
            return resp.ok
        except requests.exceptions.RequestException:
            return False

    # ------------------------------------------------------------------
    # Atlassian Document Format builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_adf_body(
        cve_id: str,
        risk_score: float,
        severity_label: str,
        description: str,
        remediation_code: str,
        code_lang: str,
        target: str,
        service: str,
    ) -> dict[str, Any]:
        """
        Build an Atlassian Document Format (ADF) body for the Jira description
        field.  ADF is required by Jira Cloud REST API v3.

        Structure
        ---------
        - Heading: "Security Finding — <CVE>"
        - Info table paragraph
        - Vulnerability description paragraph
        - Heading: "Remediation"
        - Code block (bash or yaml)
        - Heading: "RTAI Metadata"
        - Footer paragraph
        """

        def _paragraph(*texts: str) -> dict:
            return {
                "type": "paragraph",
                "content": [{"type": "text", "text": t} for t in texts],
            }

        def _heading(text: str, level: int = 2) -> dict:
            return {
                "type": "heading",
                "attrs": {"level": level},
                "content": [{"type": "text", "text": text}],
            }

        def _code_block(code: str, language: str = "bash") -> dict:
            return {
                "type": "codeBlock",
                "attrs": {"language": language},
                "content": [{"type": "text", "text": code}],
            }

        def _bullet_list(items: list[str]) -> dict:
            return {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [_paragraph(item)],
                    }
                    for item in items
                ],
            }

        info_items = [
            f"CVE: {cve_id}",
            f"Dynamic Risk Score: {risk_score} / 10  ({severity_label})",
        ]
        if target:
            info_items.append(f"Target: {target}")
        if service:
            info_items.append(f"Affected service: {service}")
        info_items.append("Source: RTAI Autonomous Red Team AI")

        # Trim remediation code to a reasonable length for the ticket
        code_preview = textwrap.shorten(
            remediation_code, width=4000, placeholder="\n... (truncated)"
        ) if len(remediation_code) > 4000 else remediation_code

        return {
            "version": 1,
            "type": "doc",
            "content": [
                _heading(f"Security Finding — {cve_id}", level=2),
                _bullet_list(info_items),
                _heading("Vulnerability Description", level=3),
                _paragraph(description or "No description provided."),
                _heading("Proposed Remediation", level=3),
                _paragraph(
                    f"The following {'Ansible playbook' if code_lang == 'yaml' else 'Bash script'} "
                    "was automatically generated by RTAI. "
                    "Review carefully before applying in production."
                ),
                _code_block(code_preview, language=code_lang),
                _heading("RTAI Metadata", level=3),
                _paragraph(
                    "This ticket was created automatically by the RTAI Autonomous "
                    "Red Team AI framework. All findings should be validated by a "
                    "qualified security engineer before remediation is applied."
                ),
            ],
        }
