from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os

app = FastAPI(
    title="AI Network Intrusion Detection System API",
    description="Machine Learning Powered NIDS Threat Detection API for Vercel",
    version="1.0.0"
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Locate model file safely (checks api/ first, then parent models/ folder)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_CANDIDATES = [
    os.path.join(CURRENT_DIR, "nids_model.pkl"),
    os.path.join(CURRENT_DIR, "..", "models", "nids_model.pkl"),
    os.path.join(os.getcwd(), "models", "nids_model.pkl"),
    os.path.join(os.getcwd(), "api", "nids_model.pkl"),
]

model = None
for candidate in MODEL_CANDIDATES:
    if os.path.exists(candidate):
        try:
            model = joblib.load(candidate)
            print(f"Loaded model successfully from: {candidate}")
            break
        except Exception as e:
            print(f"Error loading model from {candidate}: {e}")

if model is None:
    print("Warning: NIDS model file could not be found in candidate paths.")

class FlowRequest(BaseModel):
    duration: float
    src_bytes: float
    dst_bytes: float
    count: float

@app.get("/")
@app.get("/api")
@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "SentinelNet AI NIDS API",
        "model_loaded": model is not None,
        "supported_features": ["duration", "src_bytes", "dst_bytes", "count"]
    }

@app.post("/predict")
@app.post("/api/predict")
def predict_traffic(flow: FlowRequest):
    if model is None:
        raise HTTPException(status_code=500, detail="Machine learning model is not loaded on server.")
    
    try:
        # Features order matching training: duration, src_bytes, dst_bytes, count
        features = np.array([[flow.duration, flow.src_bytes, flow.dst_bytes, flow.count]], dtype=float)
        prediction = int(model.predict(features)[0])
        
        # Calculate confidence / threat score if available
        confidence = 95.0
        threat_score = 90.0 if prediction == 1 else 10.0
        
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(features)[0]
            # probs[1] is probability of attack (class 1)
            threat_score = round(float(probs[1]) * 100, 2)
            confidence = round(float(probs[prediction]) * 100, 2)
            
        is_attack = (prediction == 1)
        
        return {
            "status": "success",
            "prediction": prediction,
            "verdict": "ATTACK DETECTED" if is_attack else "NORMAL TRAFFIC",
            "is_attack": is_attack,
            "threat_score": threat_score,
            "confidence": confidence,
            "features_received": {
                "duration": flow.duration,
                "src_bytes": flow.src_bytes,
                "dst_bytes": flow.dst_bytes,
                "count": flow.count
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Prediction failed: {str(e)}")
