import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Ensure folder exists
os.makedirs("models", exist_ok=True)

# Load dataset
df = pd.read_csv("data/dataset.csv")

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="logloss"
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

print(classification_report(y_test, pred, zero_division=0))

joblib.dump(model, "models/nids_model.pkl")

print("✅ Model saved successfully!")