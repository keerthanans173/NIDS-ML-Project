import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils import resample
import warnings
warnings.filterwarnings("ignore")

# ── Put your KDD file paths here ──
TRAIN_PATH  = "data/KDDTrain+.txt"
TEST_PATH   = "data/KDDTest+.txt"
OUTPUT_PATH = "ids_model.pkl"

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

print("Loading data...")
train = pd.read_csv(TRAIN_PATH, header=None, names=columns, low_memory=False)
test  = pd.read_csv(TEST_PATH,  header=None, names=columns, low_memory=False)

train = train[train["duration"] != "duration"].reset_index(drop=True)
test  = test[test["duration"]  != "duration"].reset_index(drop=True)

train.drop("difficulty", axis=1, inplace=True)
test.drop("difficulty",  axis=1, inplace=True)

print(f"Train: {len(train)} rows | Test: {len(test)} rows")

def map_label(label):
    label = str(label).strip().lower()
    dos   = ["back","land","neptune","pod","smurf","teardrop","apache2","udpstorm","processtable","mailbomb"]
    probe = ["ipsweep","nmap","portsweep","satan","mscan","saint"]
    r2l   = ["ftp_write","guess_passwd","imap","multihop","phf","spy","warezclient","warezmaster",
             "sendmail","named","snmpgetattack","snmpguess","worm","xlock","xsnoop","httptunnel"]
    u2r   = ["buffer_overflow","loadmodule","perl","rootkit","ps","sqlattack","xterm"]
    if label == "normal":  return "Normal"
    elif label in dos:     return "DoS"
    elif label in probe:   return "Probe"
    elif label in r2l:     return "R2L"
    elif label in u2r:     return "U2R"
    else:                  return "DoS"

train["label"] = train["label"].apply(map_label)
test["label"]  = test["label"].apply(map_label)
print(f"Class distribution:\n{train['label'].value_counts()}\n")

cat_cols = ["protocol_type", "service", "flag"]
encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    combined = pd.concat([train[col], test[col]]).astype(str)
    le.fit(combined)
    train[col] = le.transform(train[col].astype(str))
    test[col]  = le.transform(test[col].astype(str))
    encoders[col] = le

print("Balancing classes...")
target_count = 3000
dfs = []
for label, group in train.groupby("label"):
    if len(group) < target_count:
        group = resample(group, replace=True, n_samples=target_count, random_state=42)
    dfs.append(group)
train_balanced = pd.concat(dfs).sample(frac=1, random_state=42).reset_index(drop=True)

target_encoder = LabelEncoder()
all_labels = list(set(train_balanced["label"].tolist() + test["label"].tolist()))
target_encoder.fit(all_labels)
y_train = target_encoder.transform(train_balanced["label"])
y_test  = target_encoder.transform(test["label"])

feature_cols = [c for c in train_balanced.columns if c != "label"]
X_train = train_balanced[feature_cols].astype(float)
X_test  = test[feature_cols].astype(float)

print("Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

print("Training Random Forest (1-2 mins)...")
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=4,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_scaled, y_train)

print("\nEvaluating...")
y_pred = model.predict(X_test_scaled)
acc = accuracy_score(y_test, y_pred)
print(f"Accuracy: {acc*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=target_encoder.classes_))

bundle = {
    "model": model,
    "scaler": scaler,
    "encoders": encoders,
    "target_encoder": target_encoder
}
with open(OUTPUT_PATH, "wb") as f:
    pickle.dump(bundle, f)

print(f"\nModel saved to: {OUTPUT_PATH}")
print("Now run: python app.py")
