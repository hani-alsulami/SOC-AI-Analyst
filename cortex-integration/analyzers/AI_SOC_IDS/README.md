# AI-SOC IDS Analyzer

A Cortex analyzer that runs the main AI-SOC project's trained CICIDS2017 models (Random Forest / XGBoost / Decision Tree) against a TheHive case, reporting a BENIGN/ATTACK classification.

## ⚠️ Read this before enabling it

**Tested and confirmed: in this environment, the classification is not reliable, and you should not act on it alone.**

The models were trained on full CICIDS2017 flow vectors — 77 statistics per network flow (packet size distributions, inter-arrival times, flag counts, byte rates...) captured by tooling like CICFlowMeter, Zeek, or Suricata. This ArcSight → TheHive environment doesn't produce that data today, so this analyzer falls back to a heuristic: it derives 2-3 features from the case's TheHive severity and whether it has `ip`/`domain` observables, leaving the other ~74 features at zero.

Testing this against the real, trained `random_forest_ids.pkl` model confirms the problem is real, not theoretical:

| Test input | ATTACK probability | BENIGN probability |
|---|---|---|
| Heuristic vector from a confirmed phishing/macro-dropper case (severity 3, SYN flag set) | 11.0% | 89.0% |
| A hand-built, more "attack-shaped" sparse vector (short flow, high packet rate, SYN+RST) | 12.6% | 87.4% |
| An all-zero vector (no signal at all) | 12.6% | 87.4% |

All three land in roughly the same place. With only 2-4 of 77 features populated, the vector doesn't resemble anything the model learned to associate with attack traffic — it just defaults toward the majority class regardless of the case's actual severity. **A confirmed-malicious case (`~1001` in the [Triage Analyzer simulation](../AI_SOC_Triage/README.md)) gets classified BENIGN here.**

### What this means practically

- Do not treat this analyzer's verdict as authoritative. `AI_SOC_Triage`'s LLM-based assessment, which reasons over the actual case description and observables, is the one to trust for triage today.
- This analyzer is included because the target architecture calls for it, and the code path is real and tested — but it needs real flow data to be useful, not just a bigger heuristic. Candidate sources: point it at Zeek/Suricata output if you deploy either at the network level, or extend ArcSight's flow-capable connectors if available in your license.
- Until real flow data is wired in, consider **not** enabling this analyzer in TheHive's UI, or labeling its output clearly as experimental so analysts don't weight it.

## Configuration

| Key | Required | Default | Notes |
|---|---|---|---|
| `thehive_url` | yes | — | e.g. `http://thehive:9000` |
| `thehive_apikey` | yes | — | TheHive API key with read access to cases |
| `models_path` | yes | — | Directory containing `random_forest_ids.pkl`, `scaler.pkl`, `label_encoder.pkl`, `feature_names.pkl` — copy these from the main project's `models/` directory to the Cortex host |
| `model_name` | no | `random_forest` | One of `random_forest`, `xgboost`, `decision_tree` |

## Output

- **Taxonomy**: `AI-SOC:IDS = BENIGN|ATTACK`. Level is `safe` for BENIGN, `suspicious` (not `malicious`) for a heuristic-path ATTACK call — the level itself signals not to fully trust it.
- **Full report**: prediction, confidence (capped at 0.5 for the heuristic path — see `HEURISTIC_CONFIDENCE_CAP` in the code), raw uncapped model confidence, class probabilities, and how many of the 77 features were actually populated.
- If there's not even severity or an ip/domain observable to build a heuristic from, it reports `prediction: "UNKNOWN"` rather than guessing.

## Local testing without a real TheHive

Same stdin pattern as `AI_SOC_Triage`:

```bash
echo '{
  "dataType": "other",
  "data": "<case-id>",
  "config": {
    "thehive_url": "http://127.0.0.1:9000",
    "thehive_apikey": "...",
    "models_path": "/path/to/SOC-AI-Analyst/models",
    "model_name": "random_forest"
  }
}' | python3 ai_soc_ids.py
```
