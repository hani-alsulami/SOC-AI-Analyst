#!/usr/bin/env python3
"""
AI-SOC IDS Analyzer for Cortex.

Loads the locally-trained CICIDS2017 models (Random Forest / XGBoost /
Decision Tree) from disk and classifies a TheHive case as BENIGN or
ATTACK, using the same feature-extraction approach as the main AI-SOC
project's alert-triage service.

IMPORTANT — read before trusting the output: these models were trained
on full CICIDS2017 network-flow feature vectors (77 features per flow,
captured by CICFlowMeter/Zeek/Suricata-style tooling). This environment
(ArcSight -> TheHive) does not currently produce that kind of flow data,
so this analyzer falls back to a small set of features heuristically
derived from the case's severity and observables. Confidence is
explicitly capped at 0.5 for this path — treat it as a supplementary
signal alongside AI_SOC_Triage, not an authoritative verdict. Wiring
this up to real flow capture is listed as a follow-up in the README.

Usage in TheHive: same pattern as AI_SOC_Triage — add an observable of
type "other" whose value is the TheHive case ID, then run this analyzer
on it.
"""

import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from cortexutils.analyzer import Analyzer
from thehive4py.api import TheHiveApi
from thehive4py.exceptions import TheHiveException
import requests

FEATURE_COUNT = 77
# Confidence ceiling for the heuristic (non-flow) extraction path — these
# features are a loose approximation, not real flow data.
HEURISTIC_CONFIDENCE_CAP = 0.5


class AISOCIDSAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "Missing thehive_url configuration"
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "Missing thehive_apikey configuration"
        )
        self.models_path = self.get_param(
            "config.models_path", None, "Missing models_path configuration"
        )
        self.model_name = self.get_param("config.model_name", "random_forest")

        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names: Optional[List[str]] = None
        self._load_models()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    _MODEL_FILES = {
        "random_forest": "random_forest_ids.pkl",
        "xgboost": "xgboost_ids.pkl",
        "decision_tree": "decision_tree_ids.pkl",
    }

    def _load_models(self):
        base = Path(self.models_path)
        model_file = self._MODEL_FILES.get(self.model_name)
        if model_file is None:
            self.error(
                f"Unknown model_name '{self.model_name}'. "
                f"Choose from: {list(self._MODEL_FILES)}"
            )

        try:
            with open(base / model_file, "rb") as f:
                self.model = pickle.load(f)
            with open(base / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            with open(base / "label_encoder.pkl", "rb") as f:
                self.label_encoder = pickle.load(f)
            with open(base / "feature_names.pkl", "rb") as f:
                self.feature_names = pickle.load(f)
        except FileNotFoundError as e:
            self.error(
                f"Model artifact not found under models_path={self.models_path}: {e}"
            )
        except Exception as e:
            self.error(f"Failed to load model artifacts: {e}")

        if len(self.feature_names) != FEATURE_COUNT:
            self.error(
                f"feature_names.pkl has {len(self.feature_names)} entries, "
                f"expected {FEATURE_COUNT} — model artifacts look mismatched"
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
            pass

        case["_observables"] = observables
        return case

    # ------------------------------------------------------------------
    # Feature extraction (heuristic path — see module docstring)
    # ------------------------------------------------------------------

    def _extract_heuristic_features(
        self, case: Dict[str, Any]
    ) -> Tuple[List[float], int]:
        """
        Port of the alert-triage service's "alert_metadata" extraction path,
        adapted to TheHive case fields (severity 1-4) instead of Wazuh rule
        levels. Indices match services/alert-triage/ml_client.py exactly.
        """
        features = [0.0] * FEATURE_COUNT
        populated = 0

        observables = case.get("_observables", [])
        has_ip = any(o.get("dataType") == "ip" for o in observables)
        has_domain = any(o.get("dataType") == "domain" for o in observables)

        if has_ip or has_domain or case.get("severity"):
            # Protocol: TCP=6, UDP=17 — assume TCP unless a domain (DNS-ish)
            # observable suggests otherwise. This is a coarse guess, not a
            # real protocol observation.
            features[0] = 17.0 if has_domain and not has_ip else 6.0
            populated += 1

            # TheHive severity (1=low .. 4=critical) as a coarse proxy for
            # the Wazuh rule_level flag-count heuristic.
            severity = case.get("severity")
            if severity:
                if severity >= 4:
                    features[44] = 1.0  # SYN Flag Count
                    features[45] = 1.0  # RST Flag Count
                    populated += 2
                elif severity >= 3:
                    features[44] = 1.0  # SYN Flag Count
                    populated += 1

            # Flow duration estimate (default 1 second) — same placeholder
            # the main project uses when no real duration is known.
            features[1] = 1000000.0
            populated += 1

        return features, populated

    # ------------------------------------------------------------------
    # cortexutils entrypoints
    # ------------------------------------------------------------------

    def summary(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        prediction = raw.get("prediction", "UNKNOWN")
        level = "info"
        if prediction == "ATTACK":
            level = "suspicious" if raw.get("source") == "heuristic" else "malicious"
        elif prediction == "BENIGN":
            level = "safe"
        return {
            "taxonomies": [
                self.build_taxonomy(level, "AI-SOC", "IDS", prediction)
            ]
        }

    def run(self):
        case_id = self.get_data()
        if not case_id:
            self.error("Observable data must be a TheHive case ID")

        case = self._fetch_case(case_id)
        features, populated = self._extract_heuristic_features(case)

        if populated == 0:
            self.report(
                {
                    "prediction": "UNKNOWN",
                    "confidence": 0.0,
                    "source": "heuristic",
                    "features_populated": 0,
                    "message": "Not enough case metadata (no severity, no ip/domain observables) to attempt classification.",
                    "case_id": case_id,
                    "model": self.model_name,
                }
            )
            return

        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)[0]
        y_proba = self.model.predict_proba(X_scaled)[0]

        predicted_class = self.label_encoder.inverse_transform([y_pred])[0]
        raw_confidence = float(np.max(y_proba))
        # Heuristic features are a loose approximation of real flow data —
        # cap confidence rather than report false precision.
        confidence = min(raw_confidence, HEURISTIC_CONFIDENCE_CAP)

        probabilities = {
            self.label_encoder.classes_[i]: float(y_proba[i])
            for i in range(len(self.label_encoder.classes_))
        }

        self.report(
            {
                "prediction": predicted_class,
                "confidence": round(confidence, 4),
                "raw_model_confidence": round(raw_confidence, 4),
                "probabilities": probabilities,
                "source": "heuristic",
                "features_populated": populated,
                "features_total": FEATURE_COUNT,
                "caveat": (
                    "Features are heuristically derived from case severity/observables, "
                    "not real network flow data. Treat as a supplementary signal."
                ),
                "case_id": case_id,
                "model": self.model_name,
            }
        )


if __name__ == "__main__":
    AISOCIDSAnalyzer().run()
