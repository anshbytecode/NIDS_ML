import os
import sys

# Ensure root directory in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import (
    BASE_DIR, DATA_DIR, MODELS_DIR, DB_PATH, REPORTS_DIR,
    NSL_KDD_COLUMNS, ATTACK_CATEGORY_MAP, MITRE_MAPPING, SEVERITY_MAPPING
)
