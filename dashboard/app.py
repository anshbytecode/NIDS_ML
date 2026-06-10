import streamlit as st
import joblib
import numpy as np
import os

# 1. Dynamically calculate the absolute path to the project root and the model file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'nids_model.pkl')

# 2. Safely load the model using the dynamic path
model = joblib.load(MODEL_PATH)

st.title('AI NIDS Dashboard')

duration = st.number_input('Duration')
src_bytes = st.number_input('Src Bytes')
dst_bytes = st.number_input('Dst Bytes')
count = st.number_input('Count')

if st.button('Predict'):
    data = np.array([[duration, src_bytes, dst_bytes, count]])
    pred = model.predict(data)[0]
    if pred == 1:
        st.error('ATTACK DETECTED')
    else:
        st.success('NORMAL TRAFFIC')