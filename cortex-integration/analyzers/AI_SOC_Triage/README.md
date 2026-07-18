# AI-SOC Triage Analyzer

A Cortex analyzer that asks a local Ollama model to triage a TheHive case: severity, MITRE ATT&CK mapping, true/false-positive call, and prioritized recommendations. No external AI API — only the TheHive and Ollama hosts configured below, both expected to be internal.

## Why this runs on a case ID, not a single observable

Cortex analyzers are normally run against one observable (an IP, hash, domain...). Triage needs the *whole* case — title, description, severity, and all its observables together — not one IOC in isolation.

Under TheHive 3.x there's no built-in "run analyzer on the whole case" action, so the accepted pattern is:

1. Add an observable of type `other` to the case, with the **case ID** as its value.
2. Run `AI_SOC_Triage` on that observable like any other analyzer.
3. The analyzer fetches the full case (and its other observables) from TheHive via the case ID, and reports back a triage assessment as this observable's Cortex report.

If your case-creation flow (e.g. the ArcSight push script) can add this `other` observable automatically when a case is created, analysts don't need step 1 manually.

## Configuration

Set these in Cortex's analyzer configuration for `AI_SOC_Triage`:

| Key | Required | Default | Notes |
|---|---|---|---|
| `thehive_url` | yes | — | e.g. `http://thehive:9000` |
| `thehive_apikey` | yes | — | TheHive API key with read access to cases |
| `ollama_host` | no | `http://localhost:11434` | Local Ollama server |
| `ollama_model` | no | `llama3.1:8b` | Must already be pulled on the Ollama host |
| `ollama_timeout_seconds` | no | `180` | CPU-only inference is slow — see note below |

## Expected latency

On a CPU-only host (no GPU), expect roughly 1-2 minutes per case with `llama3.1:8b`. This is a background-enrichment analyzer, not a live chat interface, so that's acceptable at the ~80 alerts/day volume this was sized for. If your alert volume grows significantly, revisit the model size or add a GPU.

## Output

- **Taxonomy** (shown as a badge in TheHive): `AI-SOC:Severity = <critical|high|medium|low|informational>`, colored by Cortex's standard info/safe/suspicious/malicious levels.
- **Full report**: severity, category, confidence, summary, detailed analysis, potential impact, true/false-positive call with reason, MITRE techniques/tactics, and prioritized recommendations.
- If the model's output can't be parsed as JSON, the analyzer still reports successfully with `severity: informational`, `parse_error: true`, and the raw model output in `detailed_analysis` — so a formatting hiccup surfaces as "needs manual review," not a failed job.

## Known limitations (v1)

- **No RAG context yet.** The main AI-SOC project's MITRE ATT&CK / CVE / runbook retrieval (`rag-service`) hasn't been ported here — `_build_context_block()` in `ai_soc_triage.py` is the wired-up extension point, currently returning nothing. The model triages from the case content alone.
- **Single model, no fallback.** The main project's alert-triage service tries a primary model then falls back to a secondary one; this analyzer only calls one model. Add a fallback call in `_call_ollama()` if that matters for your environment.
- **No write-back to the case.** The report only appears as this observable's Cortex analysis. Posting a summary as a case task log or comment would need `thehive4py`'s case-task-log API — not implemented here yet.

## Local testing without a real TheHive/Ollama

`ai_soc_triage.py` reads its input as JSON from stdin (the same shape Cortex's job runner writes to `input.json`):

```bash
echo '{
  "dataType": "other",
  "data": "<case-id>",
  "config": {
    "thehive_url": "http://127.0.0.1:9000",
    "thehive_apikey": "...",
    "ollama_host": "http://127.0.0.1:11434",
    "ollama_model": "llama3.1:8b"
  }
}' | python3 ai_soc_triage.py
```
