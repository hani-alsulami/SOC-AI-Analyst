# AI-SOC Block Ticket Responder

One-click workflow for a malicious IP observable in TheHive: analyst runs this Responder on the IP, it files a Jira ticket for the block request (and is meant to also submit the IP to Anomali ThreatStream — see the status below).

## Status: Jira works, Anomali is a stub

| Part | Status | Confidence |
|---|---|---|
| Jira ticket creation | **Implemented, tested** | High — Jira's REST API (v2 and v3) is stable and well-documented; tested end-to-end against a mocked Jira server (basic + bearer auth, custom fields, both ADF and plain-text description) |
| Anomali ThreatStream submission | **Not implemented — stub only** | None — no verified reference was available |

### Why Anomali isn't implemented yet

Adding an IP to a specific Anomali ThreatStream list (as opposed to general threat-intel lookup, which several public integrations exist for) isn't something there's a reliable public reference for:

- No official `anomali`/`threatstream` Python package on PyPI.
- Not present in the community [TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) repo (checked — has Redmine/RT4 ticketing responders, several other threat-intel analyzers, no Anomali).
- ThreatStream's API has changed shape across versions (v1 CSV/multipart import, v2 JSON intelligence endpoint, separate watchlist endpoints) and without a confirmed example against a real tenant, guessing the exact endpoint/payload risks silently failing — or worse, hitting the wrong endpoint — against your actual ThreatStream instance.
- **Checked and ruled out**: [CrowdStrike/foundry-sample-anomali-threatstream](https://github.com/CrowdStrike/foundry-sample-anomali-threatstream) — reviewed in full (its `Anomali.json` OpenAPI spec, ~4900 lines, plus its Python/Go function code). It only pulls data *from* Anomali into CrowdStrike (`GET /api/v2/intelligence/`), the opposite direction from what this responder needs, and contains no `list_id`/watchlist endpoint anywhere. The only submission endpoint it documents is `POST /api/v2/intelligence/import/` (`multipart/form-data`, `Authorization: Bearer <apikey>`, fields `classification`/`confidence`/`threat_type`/`datatext`/...) — confirmed real and well-specified, but it imports the observable into ThreatStream's general intelligence feed, not into a specific named list. Not a match for the "add to list X" workflow described below, so not implemented from this reference alone.

`_submit_to_anomali()` in `ai_soc_block_ticket.py` is intentionally a stub: with `anomali_enabled=false` (the default), the Jira ticket still gets filed and the report clearly says `anomali_status: "not_implemented"`. If `anomali_enabled=true` is set without finishing the implementation, the responder **fails loudly** rather than reporting a fake success — verified in testing.

**To finish it**, the fastest path is one of:
1. An example `curl`/Postman call your team already uses for this exact action (even from the ThreatStream UI's network tab), or
2. Your ThreatStream API documentation link for whichever import/watchlist endpoint your tenant uses, or
3. Tenant + list details (API base URL, the specific list ID/name indicators go into, and the auth header format) so a call can be constructed from ThreatStream's general API conventions and then verified together against a real request.

Once one of those is available, `_submit_to_anomali()` gets filled in, `anomali_enabled` flips to `true` by default, and the config fields already reserved for it (`anomali_api_url`, `anomali_username`, `anomali_api_key`, `anomali_list_id`) get used.

## Configuration

| Key | Required | Default | Notes |
|---|---|---|---|
| `jira_url` | yes | — | e.g. `https://yourorg.atlassian.net` |
| `jira_api_version` | no | `2` | `2` for Server/DC or older Cloud, `3` for current Cloud (uses Atlassian Document Format for the description) |
| `jira_auth_type` | no | `basic` | `basic` (email + API token, typical Cloud) or `bearer` (personal access token, typical Server/DC) |
| `jira_username` | if `basic` | — | Usually your Jira account email |
| `jira_api_token` | yes | — | API token (basic) or PAT (bearer) |
| `jira_project_key` | yes | — | e.g. `SOC` |
| `jira_issue_type` | no | `Task` | Must match an issue type that exists in your project |
| `jira_custom_fields_json` | no | `{}` | JSON object mapping custom field IDs to values. Supports `{ip}` and `{case_id}` placeholders, e.g. `{"customfield_10050": "{ip}"}` — get your field IDs from Jira's `/rest/api/2/field` endpoint or your admin panel |
| `anomali_enabled` | no | `false` | Leave `false` until the integration above is finished |

## Input handling

Runs on an `ip` observable. Handles two possible shapes for `data`, the same defensive pattern used elsewhere in this project since exact Cortex/TheHive bindings vary by deployment:
- A bare string (just the IP) — case context in the Jira ticket will show `N/A`.
- A dict with `data`/`case` keys (observable object with parent case attached) — case ID and title get included in the ticket description.

## Local testing without real Jira

```bash
echo '{
  "dataType": "ip",
  "data": "203.0.113.42",
  "config": {
    "jira_url": "http://127.0.0.1:9090",
    "jira_api_version": "2",
    "jira_auth_type": "basic",
    "jira_username": "you@example.com",
    "jira_api_token": "...",
    "jira_project_key": "SOC",
    "jira_custom_fields_json": "{\"customfield_10050\": \"{ip}\"}"
  }
}' | python3 ai_soc_block_ticket.py
```
