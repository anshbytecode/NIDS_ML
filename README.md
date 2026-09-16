# 🛡️ SentinelNet: Enterprise AI Network Intrusion Detection System (NIDS)

**SentinelNet** is a 100% Python-based, enterprise-grade AI/ML Network Intrusion Detection System and Security Operations Center (SOC). It combines multi-model machine learning consensus (Random Forest, XGBoost, SVM), deep autoencoder anomaly detection (PyTorch), Explainable AI (SHAP), endpoint EDR correlation (`psutil`), Geo-IP intelligence, automated containment playbooks, and incident ticketing.

---

## 🌟 100% Python Technology Stack

| Layer | Library | Purpose |
| :--- | :--- | :--- |
| **Machine Learning** | `scikit-learn`, `xgboost` | Multi-class supervised classification (RF, XGBoost, DT, SVM, KNN) |
| **Deep Learning** | `torch` (PyTorch) | Flow Autoencoder bottleneck for Zero-Day anomaly detection |
| **Explainable AI (XAI)**| `shap` | TreeExplainer for local feature attribution and contribution weighting |
| **Packet Capture** | `scapy`, `socket` | Live packet sniffing, TCP/UDP/ICMP protocol parsing, and flag analysis |
| **Flow Aggregation** | `pandas`, `numpy` | 5-tuple bidirectional session tracking and rate calculations |
| **Endpoint EDR** | `psutil` | Host CPU %, RAM %, listening ports, and socket threat correlation |
| **SOC Dashboard** | `streamlit`, `plotly` | Interactive 10-module SOC console with network graphs and world maps |
| **Database** | `sqlite3` | Local storage for alerts, incidents, blocklist, and feedback loop |
| **Audit Reports** | `reportlab` | Automated executive security audit PDF document generation |
| **REST API** | `fastapi`, `uvicorn` | High-throughput microservice for external SIEM integration |

---

Deployed : https://nidsaimlpybyanshul.streamlit.app/
