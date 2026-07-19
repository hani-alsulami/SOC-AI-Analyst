#!/usr/bin/env python3
"""
AI-SOC Block Ticket Responder for Cortex.

One-click IP block workflow, run from a malicious IP observable in
TheHive:
  1. Files a Jira ticket for the block request. VERIFIED — Jira's REST
     API (v2 and v3) is stable, standard, and this has been tested
     against a mocked Jira server.
  2. Submits the IP to Anomali ThreatStream as a blocklist indicator.
     NOT YET IMPLEMENTED. No verified reference for the exact
     endpoint/payload your ThreatStream tenant expects was available
     when this was built (no official SDK, not present in the
     community Cortex-Analyzers repo). `_submit_to_anomali()` is a
     stub — see README.md for what's needed to finish it. With
     anomali_enabled=false (the default), this responder still files
     the Jira ticket and reports anomali_status: "not_implemented" so
     nobody mistakes silence for a completed block.
"""

import base64
import json
from typing import Any, Dict, Optional

import requests
from cortexutils.responder import Responder


class AISOCBlockTicketResponder(Responder):
    def __init__(self):
        Responder.__init__(self)

        self.jira_url = self.get_param(
            "config.jira_url", None, "Missing jira_url configuration"
        ).rstrip("/")
        self.jira_api_version = str(self.get_param("config.jira_api_version", "2"))
        self.jira_auth_type = self.get_param("config.jira_auth_type", "basic")
        self.jira_username = self.get_param("config.jira_username", None)
        self.jira_api_token = self.get_param(
            "config.jira_api_token", None, "Missing jira_api_token configuration"
        )
        self.jira_project_key = self.get_param(
            "config.jira_project_key", None, "Missing jira_project_key configuration"
        )
        self.jira_issue_type = self.get_param("config.jira_issue_type", "Task")

        custom_fields_raw = self.get_param("config.jira_custom_fields_json", "{}")
        try:
            self.jira_custom_fields = json.loads(custom_fields_raw)
        except json.JSONDecodeError:
            self.error(
                f"config.jira_custom_fields_json is not valid JSON: {custom_fields_raw!r}"
            )

        self.anomali_enabled = self.get_param("config.anomali_enabled", False)

    # ------------------------------------------------------------------
    # Input resolution — observable value plus best-effort case context
    # ------------------------------------------------------------------

    def _resolve_ip_and_context(self) -> Dict[str, Any]:
        raw = self.get_data()

        if isinstance(raw, dict):
            # Some TheHive/Cortex bindings pass the full observable object
            # rather than a bare value — handle both defensively, same
            # pattern used across this project's other Cortex components.
            ip = raw.get("data", raw.get("value"))
            case = raw.get("case", {}) if isinstance(raw.get("case"), dict) else {}
            return {"ip": ip, "case_id": case.get("id"), "case_title": case.get("title")}

        return {"ip": raw, "case_id": None, "case_title": None}

    # ------------------------------------------------------------------
    # Jira — verified against a mocked server, see analyzer_venv tests
    # ------------------------------------------------------------------

    def _jira_auth_header(self) -> Dict[str, str]:
        if self.jira_auth_type == "bearer":
            return {"Authorization": f"Bearer {self.jira_api_token}"}
        # basic
        if not self.jira_username:
            self.error("config.jira_username is required when jira_auth_type is 'basic'")
        token = base64.b64encode(
            f"{self.jira_username}:{self.jira_api_token}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}"}

    def _jira_description(self, ip: str, case_id: Optional[str], case_title: Optional[str]) -> Any:
        text = (
            f"Requested by AI-SOC Responder.\n\n"
            f"IP to block: {ip}\n"
            f"Source case: {case_title or 'N/A'} ({case_id or 'N/A'})"
        )
        if self.jira_api_version == "3":
            # Jira Cloud v3 requires Atlassian Document Format for description.
            return {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": text}],
                    }
                ],
            }
        return text

    def _substitute(self, template: str, ip: str, case_id: Optional[str]) -> str:
        return template.replace("{ip}", ip).replace("{case_id}", case_id or "N/A")

    def _create_jira_ticket(
        self, ip: str, case_id: Optional[str], case_title: Optional[str]
    ) -> Dict[str, Any]:
        fields = {
            "project": {"key": self.jira_project_key},
            "summary": f"Block IP {ip} — SOC request",
            "description": self._jira_description(ip, case_id, case_title),
            "issuetype": {"name": self.jira_issue_type},
        }
        for field_id, template in self.jira_custom_fields.items():
            fields[field_id] = (
                self._substitute(template, ip, case_id)
                if isinstance(template, str)
                else template
            )

        try:
            resp = requests.post(
                f"{self.jira_url}/rest/api/{self.jira_api_version}/issue",
                headers={
                    **self._jira_auth_header(),
                    "Content-Type": "application/json",
                },
                json={"fields": fields},
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": f"Failed to reach Jira at {self.jira_url}: {e}"}

        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "error": f"Jira returned HTTP {resp.status_code}: {resp.text[:400]}",
            }

        body = resp.json()
        return {
            "status": "created",
            "key": body.get("key"),
            "url": f"{self.jira_url}/browse/{body.get('key')}" if body.get("key") else None,
        }

    # ------------------------------------------------------------------
    # Anomali — NOT IMPLEMENTED, see module docstring and README
    # ------------------------------------------------------------------

    def _submit_to_anomali(self, ip: str) -> Dict[str, Any]:
        if not self.anomali_enabled:
            return {
                "status": "not_implemented",
                "note": (
                    "Anomali ThreatStream submission is not implemented yet — "
                    "no verified API reference was available. See this "
                    "responder's README for what's needed to finish it."
                ),
            }
        # anomali_enabled=true but there is still no real implementation
        # below — fail loudly rather than pretend to have blocked anything.
        self.error(
            "anomali_enabled=true but the Anomali integration is not implemented. "
            "Set it back to false, or finish _submit_to_anomali() first."
        )

    # ------------------------------------------------------------------
    # cortexutils entrypoint
    # ------------------------------------------------------------------

    def run(self):
        ctx = self._resolve_ip_and_context()
        ip = ctx["ip"]
        if not ip:
            self.error("Could not resolve an IP value from the observable data")

        jira_result = self._create_jira_ticket(ip, ctx["case_id"], ctx["case_title"])
        anomali_result = self._submit_to_anomali(ip)

        self.report(
            {
                "ip": ip,
                "case_id": ctx["case_id"],
                "jira": jira_result,
                "anomali_status": anomali_result["status"],
                "anomali_detail": anomali_result.get("note", anomali_result.get("error")),
            }
        )


if __name__ == "__main__":
    AISOCBlockTicketResponder().run()
