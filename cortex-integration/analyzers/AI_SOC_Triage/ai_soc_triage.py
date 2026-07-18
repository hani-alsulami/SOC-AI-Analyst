#!/usr/bin/env python3
"""
AI-SOC Triage Analyzer for Cortex.

Fetches a TheHive case, asks a local Ollama model for a structured
severity/MITRE ATT&CK assessment, and reports it back as a standard
Cortex analyzer report (taxonomy + full JSON).

Usage in TheHive: add an observable of type "other" whose value is the
TheHive case ID, then run this analyzer on it. See README.md in this
directory for why case-level (not single-observable) analysis works
this way under TheHive 3.x.

No external network calls are made other than to the configured
TheHive and Ollama hosts, both expected to be on the internal network.
"""

import json
import re
from typing import Any, Dict, List, Optional

import requests
from cortexutils.analyzer import Analyzer
from thehive4py.api import TheHiveApi
from thehive4py.exceptions import TheHiveException

VALID_SEVERITIES = ["critical", "high", "medium", "low", "informational"]

# Cortex taxonomy levels: info, safe, suspicious, malicious
_SEVERITY_TO_TAXONOMY_LEVEL = {
    "critical": "malicious",
    "high": "malicious",
    "medium": "suspicious",
    "low": "safe",
    "informational": "safe",
}


class AISOCTriageAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "Missing thehive_url configuration"
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "Missing thehive_apikey configuration"
        )
        self.ollama_host = self.get_param(
            "config.ollama_host", "http://localhost:11434"
        )
        self.ollama_model = self.get_param("config.ollama_model", "llama3.1:8b")
        self.ollama_timeout_seconds = self.get_param(
            "config.ollama_timeout_seconds", 180
        )

    # ------------------------------------------------------------------
    # TheHive fetch
    # ------------------------------------------------------------------

    def _fetch_case(self, case_id: str) -> Dict[str, Any]:
        hive = TheHiveApi(self.thehive_url, self.thehive_apikey)

        try:
            case_resp = hive.get_case(case_id)
        except TheHiveException as e:
            self.error(f"Failed to reach TheHive at {self.thehive_url}: {e}")
        if case_resp.status_code != 200:
            self.error(
                f"Failed to fetch case {case_id} from TheHive: "
                f"HTTP {case_resp.status_code} — {case_resp.text[:300]}"
            )
        case = case_resp.json()

        observables: List[Dict[str, Any]] = []
        try:
            obs_resp = hive.get_case_observables(case_id)
            if obs_resp.status_code == 200:
                observables = obs_resp.json()
        except (TheHiveException, requests.exceptions.RequestException):
            # Observables are context, not required — proceed without them
            # rather than failing the whole triage on a secondary fetch.
            pass

        case["_observables"] = observables
        return case

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_context_block(self) -> str:
        """
        Extension point for RAG context (MITRE ATT&CK / CVE / runbooks via
        ChromaDB), ported from the main AI-SOC project's rag-service. Not
        wired up yet in this Cortex integration — returns empty until the
        MITRE/CVE/runbook corpus is ingested for this environment.
        """
        return ""

    def _build_triage_prompt(self, case: Dict[str, Any]) -> str:
        observables = case.get("_observables", [])
        observables_block = "\n".join(
            f"- {obs.get('dataType', 'unknown')}: {obs.get('data', 'N/A')}"
            for obs in observables[:20]
        ) or "None recorded"

        context_section = ""
        context = self._build_context_block()
        if context:
            context_section = (
                f"\n\n**ANALYST CONTEXT (use to inform your assessment):**\n"
                f"{context}\n\n---\n"
            )

        return f"""You are an expert cybersecurity analyst performing alert triage for a Security Operations Center (SOC).

**TASK:** Analyze the following TheHive case and provide a structured assessment.
{context_section}
**CASE DETAILS:**
- Case ID: {case.get('id', case.get('_id', 'N/A'))}
- Title: {case.get('title', 'N/A')}
- Description: {case.get('description', 'N/A')}
- Severity (TheHive, 1-4): {case.get('severity', 'N/A')}
- TLP: {case.get('tlp', 'N/A')}
- Tags: {', '.join(case.get('tags', [])) or 'None'}

**OBSERVABLES:**
{observables_block}

**YOUR ANALYSIS MUST INCLUDE:**
1. **Severity Assessment:** Classify as critical/high/medium/low/informational
2. **Category:** Identify attack category (malware, intrusion, exfiltration, etc)
3. **True/False Positive:** Determine if this is a genuine threat
4. **MITRE ATT&CK:** Map to relevant techniques and tactics
5. **Recommendations:** Provide 3-5 prioritized response actions

**CRITICAL RULES:**
- Base assessment ONLY on the case details and observables provided above
- If information is insufficient, state "INSUFFICIENT_DATA" in detailed_analysis
- Do NOT hallucinate IOCs or details not present in the case
- Provide a confidence score (0.0-1.0) for your assessment
- Be concise but thorough

**OUTPUT FORMAT (JSON only, no other text):**
{{
    "severity": "high",
    "category": "intrusion_attempt",
    "confidence": 0.92,
    "summary": "Brief 1-sentence summary",
    "detailed_analysis": "Technical analysis with evidence",
    "potential_impact": "Business/security impact",
    "is_true_positive": true,
    "false_positive_reason": null,
    "mitre_techniques": ["T1110.001"],
    "mitre_tactics": ["TA0006"],
    "recommendations": [
        {{"action": "Block source IP at firewall", "priority": 1, "rationale": "Prevent continued brute force attempts"}}
    ],
    "investigation_priority": 2
}}

Begin your analysis now:"""

    # ------------------------------------------------------------------
    # Ollama call
    # ------------------------------------------------------------------

    def _call_ollama(self, prompt: str) -> str:
        try:
            resp = requests.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1},
                },
                timeout=self.ollama_timeout_seconds,
            )
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to reach Ollama at {self.ollama_host}: {e}")

        if resp.status_code != 200:
            self.error(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}"
            )

        return resp.json().get("response", "")

    def _parse_llm_output(self, raw_output: str) -> Optional[Dict[str, Any]]:
        # format="json" should already return clean JSON, but strip any
        # stray markdown fences a model might still add defensively.
        cleaned = re.sub(r"^```(?:json)?|```$", "", raw_output.strip(), flags=re.MULTILINE).strip()
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return None

        if parsed.get("severity") not in VALID_SEVERITIES:
            parsed["severity"] = "informational"
        parsed.setdefault("confidence", 0.0)
        parsed.setdefault("summary", "No summary provided by model")
        parsed.setdefault("is_true_positive", False)
        parsed.setdefault("mitre_techniques", [])
        parsed.setdefault("mitre_tactics", [])
        parsed.setdefault("recommendations", [])
        return parsed

    # ------------------------------------------------------------------
    # cortexutils entrypoints
    # ------------------------------------------------------------------

    def summary(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        level = _SEVERITY_TO_TAXONOMY_LEVEL.get(raw.get("severity"), "info")
        return {
            "taxonomies": [
                self.build_taxonomy(
                    level, "AI-SOC", "Severity", raw.get("severity", "unknown")
                )
            ]
        }

    def run(self):
        case_id = self.get_data()
        if not case_id:
            self.error("Observable data must be a TheHive case ID")

        case = self._fetch_case(case_id)
        prompt = self._build_triage_prompt(case)
        raw_output = self._call_ollama(prompt)
        result = self._parse_llm_output(raw_output)

        if result is None:
            # Don't fail the whole job on a formatting hiccup — report a
            # low-confidence result the analyst can see and act on.
            self.report(
                {
                    "severity": "informational",
                    "confidence": 0.0,
                    "summary": "Model output could not be parsed as JSON — manual review needed",
                    "detailed_analysis": raw_output[:2000],
                    "is_true_positive": False,
                    "mitre_techniques": [],
                    "mitre_tactics": [],
                    "recommendations": [],
                    "parse_error": True,
                    "model": self.ollama_model,
                    "case_id": case_id,
                }
            )
            return

        result["model"] = self.ollama_model
        result["case_id"] = case_id
        self.report(result)


if __name__ == "__main__":
    AISOCTriageAnalyzer().run()
