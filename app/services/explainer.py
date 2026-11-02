"""
SentinelFlow Explainability Service
Computes SHAP feature importance per prediction and converts
top 5 contributing features into plain-English human sentences.
"""

import logging
import numpy as np
from app.ml.preprocess import ALL_FEATURES, FEATURE_METADATA

logger = logging.getLogger("sentinel.services.explainer")

FEATURE_FRIENDLY_NAMES = {
    "duration": "connection duration",
    "protocol_type": "protocol type",
    "service": "network service",
    "flag": "connection status flag",
    "src_bytes": "source byte volume",
    "dst_bytes": "destination byte volume",
    "land": "identical source and destination IP/port",
    "wrong_fragment": "corrupted packet fragments",
    "urgent": "urgent packet count",
    "hot": "sensitive directory access indicators",
    "num_failed_logins": "failed login attempts",
    "logged_in": "authenticated login session status",
    "num_compromised": "compromised system state count",
    "root_shell": "root shell spawn attempt",
    "su_attempted": "superuser privilege escalation attempt",
    "num_root": "root-level operations",
    "num_file_creations": "system file creation rate",
    "num_shells": "spawned shell prompts",
    "num_access_files": "access control file modifications",
    "num_outbound_cmds": "outbound FTP command count",
    "is_host_login": "admin host login status",
    "is_guest_login": "guest account login status",
    "count": "2-second connection burst count",
    "srv_count": "2-second same-service connection count",
    "serror_rate": "SYN error rate",
    "srv_serror_rate": "service-specific SYN error rate",
    "rerror_rate": "rejected connection rate",
    "srv_rerror_rate": "service rejection rate",
    "same_srv_rate": "same service connection ratio",
    "diff_srv_rate": "different service connection ratio",
    "srv_diff_host_rate": "different host connection ratio",
    "dst_host_count": "historical destination host frequency",
    "dst_host_srv_count": "destination host service concentration",
    "dst_host_same_srv_rate": "host same-service rate",
    "dst_host_diff_srv_rate": "host different-service rate",
    "dst_host_same_src_port_rate": "same source port reuse rate",
    "dst_host_srv_diff_host_rate": "service diff host rate",
    "dst_host_serror_rate": "host SYN error rate",
    "dst_host_srv_serror_rate": "host service SYN error rate",
    "dst_host_rerror_rate": "host rejection error rate",
    "dst_host_srv_rerror_rate": "host service rejection error rate"
}

class SentinelExplainer:
    def __init__(self, explainer=None, model=None, feature_names=None):
        self.explainer = explainer
        self.model = model
        self.feature_names = feature_names or ALL_FEATURES

    def explain_instance(self, X_scaled: np.ndarray, raw_features: dict, predicted_class: str, class_idx: int = 0) -> dict:
        """
        Calculates SHAP values or feature attribution for an instance.
        Returns top 5 contributing features and a plain-English explanation.
        """
        top_features = []
        shap_values_dict = {}

        # 1. Attempt SHAP TreeExplainer
        if self.explainer is not None:
            try:
                shap_res = self.explainer(X_scaled)
                # shap_res.values shape can be [1, n_features, n_classes] or [1, n_features]
                vals = shap_res.values[0]
                if vals.ndim == 2:
                    class_vals = vals[:, class_idx]
                else:
                    class_vals = vals

                for i, feat in enumerate(self.feature_names):
                    shap_values_dict[feat] = float(class_vals[i])
            except Exception as e:
                logger.debug(f"TreeExplainer inference fallback: {e}")
                shap_values_dict = self._fallback_attribution(X_scaled, raw_features, predicted_class)
        else:
            shap_values_dict = self._fallback_attribution(X_scaled, raw_features, predicted_class)

        # 2. Rank top 5 by absolute impact
        sorted_feats = sorted(shap_values_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        
        for feat, val in sorted_feats:
            raw_val = raw_features.get(feat, "")
            friendly = FEATURE_FRIENDLY_NAMES.get(feat, feat)
            top_features.append({
                "feature": feat,
                "friendly_name": friendly,
                "importance": round(val, 4),
                "raw_value": raw_val,
                "impact": "positive" if val >= 0 else "negative"
            })

        # 3. Generate plain-English explanation sentence
        sentence = self._generate_english_sentence(predicted_class, top_features, raw_features)

        return {
            "top_features": top_features,
            "plain_english": sentence
        }

    def _fallback_attribution(self, X_scaled: np.ndarray, raw_features: dict, predicted_class: str) -> dict:
        """Fallback attribution based on feature importances and anomaly deviations."""
        attr = {}
        importances = getattr(self.model, "feature_importances_", None)
        scaled_vec = X_scaled[0] if X_scaled.ndim == 2 else X_scaled

        for i, feat in enumerate(self.feature_names):
            base_imp = float(importances[i]) if importances is not None and i < len(importances) else 0.02
            z_score = float(scaled_vec[i]) if i < len(scaled_vec) else 0.0
            # Higher deviation in an attack increases attribution
            if predicted_class != "Normal":
                attr[feat] = round(base_imp * (1.0 + abs(z_score)), 4)
            else:
                attr[feat] = round(base_imp * max(0.1, 1.0 - abs(z_score)), 4)
        return attr

    def _generate_english_sentence(self, predicted_class: str, top_features: list, raw_features: dict) -> str:
        """Synthesizes a cohesive plain-English sentence describing the detection rationale."""
        if not top_features:
            return f"Traffic categorized as {predicted_class} based on baseline model heuristics."

        f1 = top_features[0]
        f2 = top_features[1] if len(top_features) > 1 else None

        val1_str = f" ({f1['raw_value']})" if f1['raw_value'] != "" else ""
        val2_str = f" and {f2['friendly_name']} ({f2['raw_value']})" if f2 and f2['raw_value'] != "" else ""

        if predicted_class == "Normal":
            return (
                f"Classified as Safe traffic because key parameters including "
                f"{f1['friendly_name']}{val1_str}{val2_str} align with standard legitimate session baselines."
            )
        elif predicted_class == "DoS":
            return (
                f"Flagged as Denial-of-Service (DoS) attack primarily driven by abnormal "
                f"{f1['friendly_name']}{val1_str}{val2_str}, indicating resource exhaustion or SYN flood characteristics."
            )
        elif predicted_class == "Probe":
            return (
                f"Flagged as Reconnaissance/Probe scan due to suspicious patterns in "
                f"{f1['friendly_name']}{val1_str}{val2_str}, consistent with port scanning or host discovery."
            )
        elif predicted_class == "R2L":
            return (
                f"Flagged as Remote-to-Local (R2L) intrusion attempt based on unauthorized access telemetry in "
                f"{f1['friendly_name']}{val1_str}{val2_str}."
            )
        elif predicted_class == "U2R":
            return (
                f"Flagged as Critical User-to-Root (U2R) privilege escalation based on anomalous payload activity in "
                f"{f1['friendly_name']}{val1_str}{val2_str}."
            )
        else:
            return f"Classified as {predicted_class} due to prominent anomalies in {f1['friendly_name']}{val1_str}."
