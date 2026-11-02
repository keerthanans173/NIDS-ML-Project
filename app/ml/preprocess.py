"""
SentinelFlow Preprocessing & Feature Engineering Pipeline
Handles data cleaning, 5-class label mapping, categorical encoding,
and scaling for NSL-KDD datasets and real-time network traffic records.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

ALL_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

CAT_FEATURES = ["protocol_type", "service", "flag"]
NUM_FEATURES = [f for f in ALL_FEATURES if f not in CAT_FEATURES]

FEATURE_GROUPS = {
    "basic": {
        "title": "Basic Connection Features",
        "description": "Fundamental transport layer connection characteristics",
        "features": ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent"]
    },
    "content": {
        "title": "Content / Payload Features",
        "description": "Payload indicators such as login attempts, root access, and file operations",
        "features": [
            "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
            "su_attempted", "num_root", "num_file_creations", "num_shells",
            "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login"
        ]
    },
    "traffic": {
        "title": "Traffic & Rate Features",
        "description": "Statistical connection windows (2-second window & host-based destination history)",
        "features": [
            "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
            "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
            "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
        ]
    }
}

FEATURE_METADATA = {
    "duration": {"label": "Duration (s)", "type": "number", "default": 0, "min": 0, "max": 60000, "tooltip": "Length of connection in seconds"},
    "protocol_type": {"label": "Protocol", "type": "select", "options": ["tcp", "udp", "icmp"], "default": "tcp", "tooltip": "Transport layer protocol"},
    "service": {"label": "Service", "type": "select", "options": [
        "http", "smtp", "ftp", "ftp_data", "ssh", "telnet", "dns", "domain_u", "eco_i", "ecr_i",
        "private", "finger", "time", "auth", "pop_3", "other"
    ], "default": "http", "tooltip": "Destination network service/port type"},
    "flag": {"label": "Connection Flag", "type": "select", "options": [
        "SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "S2", "S3", "OTH"
    ], "default": "SF", "tooltip": "Connection status (SF: Normal, S0: Connection attempt without response, REJ: Rejected)"},
    "src_bytes": {"label": "Source Bytes", "type": "number", "default": 215, "min": 0, "max": 100000000, "tooltip": "Bytes sent from client to server"},
    "dst_bytes": {"label": "Destination Bytes", "type": "number", "default": 450, "min": 0, "max": 100000000, "tooltip": "Bytes sent from server to client"},
    "land": {"label": "Land Attack Flag", "type": "select", "options": [0, 1], "default": 0, "tooltip": "1 if source and destination IP/port match exactly"},
    "wrong_fragment": {"label": "Wrong Fragments", "type": "number", "default": 0, "min": 0, "max": 3, "tooltip": "Number of corrupted packet fragments"},
    "urgent": {"label": "Urgent Packets", "type": "number", "default": 0, "min": 0, "max": 10, "tooltip": "Number of TCP urgent packets"},
    "hot": {"label": "Hot Indicators", "type": "number", "default": 0, "min": 0, "max": 100, "tooltip": "Number of 'hot' indicators (e.g. entering sensitive directories)"},
    "num_failed_logins": {"label": "Failed Logins", "type": "number", "default": 0, "min": 0, "max": 10, "tooltip": "Count of failed authentication attempts"},
    "logged_in": {"label": "Logged In", "type": "select", "options": [0, 1], "default": 1, "tooltip": "1 if successfully authenticated/logged in"},
    "num_compromised": {"label": "Compromised Conditions", "type": "number", "default": 0, "min": 0, "max": 100, "tooltip": "Count of compromised file/system states"},
    "root_shell": {"label": "Root Shell", "type": "select", "options": [0, 1], "default": 0, "tooltip": "1 if root/admin shell was spawned"},
    "su_attempted": {"label": "SU Attempted", "type": "select", "options": [0, 1], "default": 0, "tooltip": "1 if 'su root' command was attempted"},
    "num_root": {"label": "Root Operations", "type": "number", "default": 0, "min": 0, "max": 100, "tooltip": "Number of operations executed as root"},
    "num_file_creations": {"label": "File Creations", "type": "number", "default": 0, "min": 0, "max": 100, "tooltip": "Number of system files created"},
    "num_shells": {"label": "Shell Prompts", "type": "number", "default": 0, "min": 0, "max": 10, "tooltip": "Number of spawned shell processes"},
    "num_access_files": {"label": "Access Files", "type": "number", "default": 0, "min": 0, "max": 10, "tooltip": "Number of operations on access control files"},
    "num_outbound_cmds": {"label": "Outbound Commands", "type": "number", "default": 0, "min": 0, "max": 10, "tooltip": "Outbound commands in ftp session"},
    "is_host_login": {"label": "Host Login", "type": "select", "options": [0, 1], "default": 0, "tooltip": "1 if login belongs to admin/host list"},
    "is_guest_login": {"label": "Guest Login", "type": "select", "options": [0, 1], "default": 0, "tooltip": "1 if login belongs to guest account"},
    "count": {"label": "Connection Count (2s)", "type": "number", "default": 1, "min": 0, "max": 511, "tooltip": "Connections to same destination IP in past 2 seconds"},
    "srv_count": {"label": "Service Count (2s)", "type": "number", "default": 1, "min": 0, "max": 511, "tooltip": "Connections to same port/service in past 2 seconds"},
    "serror_rate": {"label": "SYN Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections with SYN errors"},
    "srv_serror_rate": {"label": "Srv SYN Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to service with SYN errors"},
    "rerror_rate": {"label": "REJ Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections with REJ errors"},
    "srv_rerror_rate": {"label": "Srv REJ Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to service with REJ errors"},
    "same_srv_rate": {"label": "Same Service Rate", "type": "number", "default": 1.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to same service"},
    "diff_srv_rate": {"label": "Diff Service Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to different services"},
    "srv_diff_host_rate": {"label": "Srv Diff Host Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to different hosts"},
    "dst_host_count": {"label": "Dst Host Count", "type": "number", "default": 100, "min": 0, "max": 255, "tooltip": "Connections having same destination IP in historical window"},
    "dst_host_srv_count": {"label": "Dst Host Srv Count", "type": "number", "default": 100, "min": 0, "max": 255, "tooltip": "Connections having same dest IP and service"},
    "dst_host_same_srv_rate": {"label": "Dst Same Srv Rate", "type": "number", "default": 1.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to same service on dest host"},
    "dst_host_diff_srv_rate": {"label": "Dst Diff Srv Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to diff services on dest host"},
    "dst_host_same_src_port_rate": {"label": "Dst Same Src Port Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections from same source port on dest host"},
    "dst_host_srv_diff_host_rate": {"label": "Dst Srv Diff Host Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to diff hosts for same service"},
    "dst_host_serror_rate": {"label": "Dst SYN Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections with SYN errors to dest host"},
    "dst_host_srv_serror_rate": {"label": "Dst Srv SYN Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to service with SYN errors to dest host"},
    "dst_host_rerror_rate": {"label": "Dst REJ Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections with REJ errors to dest host"},
    "dst_host_srv_rerror_rate": {"label": "Dst Srv REJ Error Rate", "type": "number", "default": 0.0, "min": 0.0, "max": 1.0, "step": 0.01, "tooltip": "% of connections to service with REJ errors to dest host"}
}

DEFAULT_FEATURE_VALUES = {k: v["default"] for k, v in FEATURE_METADATA.items()}

# 5 Attack Classes Mapping
ATTACK_CATEGORIES = {
    "DoS": ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2", "udpstorm", "processtable", "mailbomb"],
    "Probe": ["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"],
    "R2L": [
        "ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster",
        "sendmail", "named", "snmpgetattack", "snmpguess", "worm", "xlock", "xsnoop", "httptunnel"
    ],
    "U2R": ["buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm"]
}

CLASS_NAMES = ["Normal", "DoS", "Probe", "R2L", "U2R"]

def map_raw_label(label: str) -> str:
    """Maps NSL-KDD fine-grained attack string to 5 primary categories."""
    lbl = str(label).strip().lower().rstrip(".")
    if lbl == "normal":
        return "Normal"
    for cat, attacks in ATTACK_CATEGORIES.items():
        if lbl in attacks:
            return cat
    return "DoS"

# Presets for manual form testing
PRESETS = {
    "Normal": {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 215, "dst_bytes": 450, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
        "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
        "dst_host_count": 100, "dst_host_srv_count": 100, "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
    },
    "DoS": {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
        "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 250, "srv_count": 15,
        "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 0.06, "diff_srv_rate": 0.07, "srv_diff_host_rate": 0.0,
        "dst_host_count": 255, "dst_host_srv_count": 15, "dst_host_same_srv_rate": 0.06,
        "dst_host_diff_srv_rate": 0.07, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
    },
    "Probe": {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "REJ",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
        "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 120, "srv_count": 3,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 1.0, "srv_rerror_rate": 1.0,
        "same_srv_rate": 0.02, "diff_srv_rate": 0.12, "srv_diff_host_rate": 0.0,
        "dst_host_count": 255, "dst_host_srv_count": 3, "dst_host_same_srv_rate": 0.01,
        "dst_host_diff_srv_rate": 0.10, "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 1.0, "dst_host_srv_rerror_rate": 1.0
    },
    "R2L": {
        "duration": 28, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
        "src_bytes": 1250, "dst_bytes": 4820, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 3, "num_failed_logins": 5, "logged_in": 1, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
        "num_shells": 0, "num_access_files": 1, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 1, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
        "dst_host_count": 10, "dst_host_srv_count": 2, "dst_host_same_srv_rate": 0.2,
        "dst_host_diff_srv_rate": 0.1, "dst_host_same_src_port_rate": 0.1,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
    },
    "U2R": {
        "duration": 54, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
        "src_bytes": 260, "dst_bytes": 2850, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 2, "num_failed_logins": 0, "logged_in": 1, "num_compromised": 3,
        "root_shell": 1, "su_attempted": 1, "num_root": 4, "num_file_creations": 2,
        "num_shells": 1, "num_access_files": 2, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
        "dst_host_count": 5, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 0.2,
        "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
    }
}


class SentinelDataPipeline:
    """
    Self-contained preprocessing pipeline that stores encoders, scaler,
    feature names, and target mappings in one serialized object.
    Guarantees training and prediction features never drift apart.
    """
    def __init__(self):
        self.feature_names = list(ALL_FEATURES)
        self.cat_features = list(CAT_FEATURES)
        self.num_features = list(NUM_FEATURES)
        self.encoders = {}
        self.scaler = StandardScaler()
        self.target_encoder = LabelEncoder()
        self.classes_ = CLASS_NAMES

    def fit(self, df_train: pd.DataFrame, y_labels: pd.Series):
        # 1. Fit categorical encoders
        for col in self.cat_features:
            le = LabelEncoder()
            # Support any unseen values with a safe unknown bucket
            unique_vals = list(df_train[col].astype(str).unique())
            if "unknown" not in unique_vals:
                unique_vals.append("unknown")
            le.fit(unique_vals)
            self.encoders[col] = le

        # 2. Transform categorical features for scaler fit
        df_encoded = self._encode_cats(df_train)

        # 3. Fit scaler
        X_num = df_encoded[self.feature_names].astype(float)
        self.scaler.fit(X_num)

        # 4. Fit target encoder
        self.target_encoder.fit(self.classes_)
        return self

    def _encode_cats(self, df: pd.DataFrame) -> pd.DataFrame:
        df_out = df.copy()
        for col in self.cat_features:
            le = self.encoders[col]
            classes_set = set(le.classes_)
            # Map unseen to classes_[0]
            first_class = le.classes_[0]
            col_vals = df_out[col].astype(str).apply(lambda x: x if x in classes_set else first_class)
            df_out[col] = le.transform(col_vals)
        return df_out

    def transform_single(self, input_dict: dict) -> np.ndarray:
        """Transforms a single feature dictionary into a scaled 2D array [1, 41]."""
        # Populate defaults for any missing features
        complete = {}
        for f in self.feature_names:
            val = input_dict.get(f, DEFAULT_FEATURE_VALUES.get(f, 0))
            if f in self.cat_features:
                complete[f] = str(val).strip().lower()
            else:
                try:
                    complete[f] = float(val)
                except (ValueError, TypeError):
                    complete[f] = float(DEFAULT_FEATURE_VALUES.get(f, 0.0))

        df = pd.DataFrame([complete])
        df_encoded = self._encode_cats(df)
        X_vals = df_encoded[self.feature_names].astype(float).values
        return self.scaler.transform(X_vals)

    def transform_df(self, df: pd.DataFrame) -> np.ndarray:
        """Transforms a DataFrame containing network traffic features."""
        df_clean = df.copy()
        for f in self.feature_names:
            if f not in df_clean.columns:
                df_clean[f] = DEFAULT_FEATURE_VALUES.get(f, 0)

        for col in self.cat_features:
            df_clean[col] = df_clean[col].astype(str).str.strip().str.lower()

        df_encoded = self._encode_cats(df_clean[self.feature_names])
        X_vals = df_encoded[self.feature_names].astype(float).values
        return self.scaler.transform(X_vals)
