import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from src.config import MODELS_DIR

# 25 primary features for fast, accurate tabular inference and live packet extraction
SELECTED_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count"
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
NUMERICAL_COLS = [c for c in SELECTED_FEATURES if c not in CATEGORICAL_COLS]

class NIDSPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.cat_mappings = {}
        self.feature_names = []
        self.is_fitted = False
        
    def fit(self, df: pd.DataFrame, target_col="attack_category"):
        X = df[SELECTED_FEATURES].copy()
        
        # Build categorical mappings
        for col in CATEGORICAL_COLS:
            unique_vals = sorted(X[col].astype(str).unique().tolist())
            self.cat_mappings[col] = {val: idx for idx, val in enumerate(unique_vals)}
            # Encode categorical to integers
            X[col] = X[col].astype(str).map(lambda v: self.cat_mappings[col].get(v, -1))
            
        # Fit scaler on numerical features
        self.scaler.fit(X[NUMERICAL_COLS])
        
        # Fit target label encoder
        y = df[target_col].copy()
        self.label_encoder.fit(y)
        
        self.feature_names = SELECTED_FEATURES
        self.is_fitted = True
        return self
        
    def transform(self, df: pd.DataFrame):
        X = df[SELECTED_FEATURES].copy()
        
        for col in CATEGORICAL_COLS:
            mapping = self.cat_mappings.get(col, {})
            X[col] = X[col].astype(str).map(lambda v: mapping.get(v, -1))
            
        # Scale numerical
        X[NUMERICAL_COLS] = self.scaler.transform(X[NUMERICAL_COLS])
        return X
        
    def transform_single(self, flow_dict: dict):
        """Converts a single flow dictionary (from packet sniffer/API) into a model input vector."""
        row = {}
        for col in SELECTED_FEATURES:
            row[col] = [flow_dict.get(col, 0)]
        df_single = pd.DataFrame(row)
        return self.transform(df_single)
        
    def save(self, directory=MODELS_DIR):
        os.makedirs(directory, exist_ok=True)
        joblib.dump(self.scaler, os.path.join(directory, "scaler.joblib"))
        joblib.dump(self.label_encoder, os.path.join(directory, "label_encoder.joblib"))
        
        meta = {
            "cat_mappings": self.cat_mappings,
            "feature_names": self.feature_names,
            "classes": self.label_encoder.classes_.tolist()
        }
        with open(os.path.join(directory, "preprocessor_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)
        print(f"✅ Saved preprocessor artifacts to {directory}")
        
    def load(self, directory=MODELS_DIR):
        scaler_path = os.path.join(directory, "scaler.joblib")
        le_path = os.path.join(directory, "label_encoder.joblib")
        meta_path = os.path.join(directory, "preprocessor_meta.json")
        
        if not (os.path.exists(scaler_path) and os.path.exists(meta_path)):
            raise FileNotFoundError(f"Preprocessor artifacts missing in {directory}")
            
        self.scaler = joblib.load(scaler_path)
        if os.path.exists(le_path):
            self.label_encoder = joblib.load(le_path)
            
        with open(meta_path, "r") as f:
            meta = json.load(f)
            self.cat_mappings = meta["cat_mappings"]
            self.feature_names = meta["feature_names"]
        self.is_fitted = True
        return self
