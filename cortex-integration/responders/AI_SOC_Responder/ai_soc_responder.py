#!/usr/bin/env python3
"""
AI-SOC Responder for Cortex.

Reads a TheHive case's mitre:Txxxx tags, looks up D3FEND-mapped
countermeasures for each technique via d3fend_mapping.py, and reports
a PROPOSED response plan. Optionally writes that plan back to the
case as a task + task log so the analyst sees it in TheHive directly,
not just in Cortex's job report.

This never executes anything. firewall/EDR/identity adapters are not
wired to real systems in this environment yet (see the D3FEND mapping
module's AdapterType — it's descriptive metadata, not a live
connection). Running this Responder is itself the analyst's deliberate
action; the analyst then carries out whichever proposed steps they
judge appropriate, through whatever tools they already use.

Two input modes are supported, since the exact TheHive3/Cortex3
data-type binding for case-level responders varies by deployment —
see README.md:
  - dataType "thehive:case": self.get_data() is the full case object,
    supplied directly by TheHive.
  - dataType "other" (fallback): self.get_data() is a case ID string;
    this responder fetches the case itself via thehive4py, the same
    pattern AI_SOC_Triage and AI_SOC_IDS use.
"""

import re
from typing import Any, Dict, List

from cortexutils.responder import Responder
from thehive4py.api import TheHiveApi
from thehive4py.exceptions import TheHiveException
from thehive4py.models import CaseTask, CaseTaskLog

from d3fend_mapping import D3FENDTechnique, get_unique_actions_for_incident

MITRE_TAG_PATTERN = re.compile(r"mitre:(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)


class AISOCResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "Missing thehive_url configuration"
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "Missing thehive_apikey configuration"
        )
        self.write_back_to_case = self.get_param("config.write_back_to_case", True)

    # ------------------------------------------------------------------
    # Case resolution (see module docstring — two input modes)
    # ------------------------------------------------------------------

    def _resolve_case(self) -> Dict[str, Any]:
        data = self.get_data()

        if isinstance(data, dict):
            return data

        # Fallback: data is a case ID string, fetch it ourselves.
        case_id = data
        hive = TheHiveApi(self.thehive_url, self.thehive_apikey)
        try:
            resp = hive.get_case(case_id)
        except TheHiveException as e:
            self.error(f"Failed to reach TheHive at {self.thehive_url}: {e}")
        if resp.status_code != 200:
            self.error(
                f"Failed to fetch case {case_id} from TheHive: "
                f"HTTP {resp.status_code} — {resp.text[:300]}"
            )
        return resp.json()

    # ------------------------------------------------------------------
    # Plan construction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_mitre_techniques(case: Dict[str, Any]) -> List[str]:
        tags = case.get("tags", [])
        found = []
        for tag in tags:
            m = MITRE_TAG_PATTERN.search(tag)
            if m:
                found.append(m.group(1).upper())
        return found

    @staticmethod
    def _plan_to_text(case_title: str, actions: List[D3FENDTechnique]) -> str:
        lines = [
            f"AI-SOC Proposed Response Plan for: {case_title}",
            "",
            "This is a PROPOSAL only — nothing was executed automatically.",
            "",
        ]
        for i, a in enumerate(actions, 1):
            lines.append(
                f"{i}. [{a.tactic}] {a.label} ({a.technique_id})\n"
                f"   Action: {a.action_type.value} via {a.adapter.value} adapter (not connected yet)\n"
                f"   Blast radius: {a.blast_radius.value} — baseline safety score: {a.default_safety}\n"
                f"   {a.description}"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # TheHive write-back
    # ------------------------------------------------------------------

    def _write_plan_to_case(self, case_id: str, plan_text: str) -> bool:
        hive = TheHiveApi(self.thehive_url, self.thehive_apikey)
        try:
            task_resp = hive.create_case_task(
                case_id,
                CaseTask(title="AI-SOC Proposed Response Plan", flag=True),
            )
            if task_resp.status_code not in (200, 201):
                return False
            task_id = task_resp.json().get("id")
            log_resp = hive.create_task_log(task_id, CaseTaskLog(message=plan_text))
            return log_resp.status_code in (200, 201)
        except (TheHiveException, Exception):
            return False

    # ------------------------------------------------------------------
    # cortexutils entrypoint
    # ------------------------------------------------------------------

    def run(self):
        case = self._resolve_case()
        case_id = case.get("id", case.get("_id"))
        case_title = case.get("title", "(untitled case)")

        technique_ids = self._extract_mitre_techniques(case)
        if not technique_ids:
            self.report(
                {
                    "status": "no_action_proposed",
                    "reason": (
                        "No mitre:Txxxx tags found on this case. Tag it with the "
                        "MITRE techniques involved (e.g. from AI_SOC_Triage's "
                        "mitre_techniques field) before running this responder."
                    ),
                    "case_id": case_id,
                }
            )
            return

        actions = get_unique_actions_for_incident(technique_ids)
        if not actions:
            self.report(
                {
                    "status": "no_action_proposed",
                    "reason": f"No D3FEND mapping found for technique(s): {technique_ids}",
                    "mitre_techniques": technique_ids,
                    "case_id": case_id,
                }
            )
            return

        plan_text = self._plan_to_text(case_title, actions)
        written_back = False
        if self.write_back_to_case and self.thehive_url and self.thehive_apikey:
            written_back = self._write_plan_to_case(case_id, plan_text)

        self.report(
            {
                "status": "plan_proposed",
                "executed": False,
                "note": "Proposal only. No firewall/EDR/identity action was executed — adapters are not connected in this environment yet.",
                "mitre_techniques": technique_ids,
                "proposed_actions": [
                    {
                        "d3fend_technique": a.technique_id,
                        "label": a.label,
                        "tactic": a.tactic,
                        "action_type": a.action_type.value,
                        "adapter": a.adapter.value,
                        "blast_radius": a.blast_radius.value,
                        "baseline_safety_score": a.default_safety,
                        "description": a.description,
                    }
                    for a in actions
                ],
                "written_back_to_case": written_back,
                "case_id": case_id,
            }
        )


if __name__ == "__main__":
    AISOCResponder().run()
