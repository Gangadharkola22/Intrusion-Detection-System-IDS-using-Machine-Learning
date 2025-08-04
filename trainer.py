import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Load all CSVs
normal_df = pd.read_csv("data/normal.csv")
scan_df = pd.read_csv("data/scan.csv")
dos_df = pd.read_csv("data/dos.csv")

# Combine all
df = pd.concat([normal_df, scan_df, dos_df], ignore_index=True)

# Encode protocol
df['protocol'] = df['protocol'].astype(str)
proto_encoder = LabelEncoder()
df['protocol_encoded'] = proto_encoder.fit_transform(df['protocol'])

# Encode label
label_encoder = LabelEncoder()
df['label_encoded'] = label_encoder.fit_transform(df['label'])

# Features
X = df[['protocol_encoded', 'sport', 'dport', 'packet_len']]
y = df['label_encoded']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

print("[✔] Model trained successfully.")
print("[ℹ] Accuracy on test set:", clf.score(X_test, y_test))

# Save model and encoders
joblib.dump(clf, 'model/ids_model.pkl')
joblib.dump(label_encoder, 'model/label_encoder.pkl')
joblib.dump(proto_encoder, 'model/protocol_encoder.pkl')
