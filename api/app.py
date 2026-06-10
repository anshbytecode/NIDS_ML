from fastapi import FastAPI
import joblib
import numpy as np

app = FastAPI()
model = joblib.load('../models/nids_model.pkl')

@app.get('/')
def home():
    return {'message': 'NIDS API Running'}

@app.post('/predict')
def predict(data: dict):
    features = np.array(list(data.values())).reshape(1, -1)
    pred = model.predict(features)[0]
    return {'result': 'ATTACK' if pred==1 else 'NORMAL'}
