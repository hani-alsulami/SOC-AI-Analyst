# AI-SOC Responder

A Cortex Responder that reads a TheHive case's `mitre:Txxxx` tags, maps them to D3FEND-mapped countermeasures (ported from the main AI-SOC project's `response-orchestrator/d3fend.py`), and reports a **proposed** response plan. Optionally writes that plan into the case as a task + task log.

## This never executes anything

Unlike the main AI-SOC project's `response-orchestrator` (which has a graduated-autonomy model with auto-execution above a confidence threshold), this Responder **always** only proposes. There is no auto-execute path, no confidence threshold, no config flag to turn on execution. Running the Responder at all is itself the analyst's deliberate, manual action — that's the approval gate, by design, matching this environment's stub adapters (no firewall/EDR/identity system is actually connected yet).

The `adapter` field in each proposed action (`wazuh`, `firewall`, `edr`, `identity`, `network`) is descriptive metadata carried over from the original D3FEND mapping — it names which *kind* of system would carry out the action in a fully wired deployment, not a live connection this Responder has.

## Where the MITRE tags come from

This Responder doesn't run any analysis itself — it reads `mitre:Txxxx` tags already on the case. The natural source is `AI_SOC_Triage`'s `mitre_techniques` output: after triaging a case, an analyst (or a small automation you add later) copies those technique IDs onto the case as tags, then runs this Responder to get the corresponding D3FEND-mapped proposal.

If a case has no `mitre:` tags, this Responder reports `no_action_proposed` with that reason rather than guessing.

## Two input modes

TheHive3/Cortex3's exact data-type binding for case-level Responders can vary by deployment, so this Responder handles both:

- **`dataType: "thehive:case"`** — TheHive supplies the full case object directly as `data`. This is the expected path when bound as a native case Responder.
- **`dataType: "other"`** (fallback) — `data` is a case ID string; the Responder fetches the case itself via `thehive4py`, the same pattern `AI_SOC_Triage` and `AI_SOC_IDS` use. Use this if the native case-responder binding doesn't behave as expected in your Cortex admin panel — verify against your actual instance, since this is the one piece of this integration not testable without a live TheHive/Cortex.

## Configuration

| Key | Required | Default | Notes |
|---|---|---|---|
| `thehive_url` | yes | — | e.g. `http://thehive:9000` |
| `thehive_apikey` | yes | — | Needs case-fetch access; needs task/task-log write access too if `write_back_to_case` is on |
| `write_back_to_case` | no | `true` | Create a task + task log with the plan, in addition to the Cortex report |

## Output

```json
{
  "status": "plan_proposed",
  "executed": false,
  "mitre_techniques": ["T1566.001"],
  "proposed_actions": [
    {
      "d3fend_technique": "d3f:InboundTrafficFiltering",
      "label": "Inbound Traffic Filtering",
      "tactic": "Isolate",
      "action_type": "block_ip",
      "adapter": "wazuh",
      "blast_radius": "low",
      "baseline_safety_score": 0.92,
      "description": "Restrict inbound network traffic from specific sources"
    }
  ],
  "written_back_to_case": true,
  "case_id": "~1001"
}
```

`status` is one of `plan_proposed` or `no_action_proposed` (no MITRE tags, or no D3FEND mapping for the tags present).

## Local testing without a real TheHive

```bash
echo '{
  "dataType": "other",
  "data": "<case-id>",
  "config": {
    "thehive_url": "http://127.0.0.1:9000",
    "thehive_apikey": "...",
    "write_back_to_case": true
  }
}' | python3 ai_soc_responder.py
```

Or test the direct-object path without any TheHive call at all:

```bash
echo '{
  "dataType": "thehive:case",
  "data": {"id": "~1", "title": "test", "tags": ["mitre:T1110"]},
  "config": {"thehive_url": "http://127.0.0.1:9000", "thehive_apikey": "...", "write_back_to_case": false}
}' | python3 ai_soc_responder.py
```
