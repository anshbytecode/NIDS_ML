import os
import shutil
import pandas as pd
from src.config import DATA_DIR, NSL_KDD_COLUMNS, ATTACK_CATEGORY_MAP

SOURCE_NSL_KDD_DIRS = [
    r"c:\Users\hp\OneDrive\Desktop\anshnew\infosys\nsl-kdd",
    r"c:\Users\hp\OneDrive\Desktop\anshnew\infosys"
]

def ensure_dataset_available():
    train_dest = os.path.join(DATA_DIR, "KDDTrain+.txt")
    test_dest = os.path.join(DATA_DIR, "KDDTest+.txt")
    
    if not os.path.exists(train_dest):
        for src_dir in SOURCE_NSL_KDD_DIRS:
            # Prefer 20Percent for swift, responsive training if present, or full
            src_train_20 = os.path.join(src_dir, "KDDTrain+_20Percent.txt")
            src_train_full = os.path.join(src_dir, "KDDTrain+.txt")
            src_test = os.path.join(src_dir, "KDDTest+.txt")
            
            src_train = src_train_20 if os.path.exists(src_train_20) else src_train_full
            
            if os.path.exists(src_train) and not os.path.exists(train_dest):
                print(f"Copying training dataset from {src_train} -> {train_dest}")
                shutil.copyfile(src_train, train_dest)
            
            if os.path.exists(src_test) and not os.path.exists(test_dest):
                print(f"Copying test dataset from {src_test} -> {test_dest}")
                shutil.copyfile(src_test, test_dest)

def load_nsl_kdd(train_file="KDDTrain+.txt", test_file="KDDTest+.txt", sample_size=None):
    ensure_dataset_available()
    train_path = os.path.join(DATA_DIR, train_file)
    test_path = os.path.join(DATA_DIR, test_file)
    
    if not os.path.exists(train_path):
        raise FileNotFoundError(f"Training dataset not found at {train_path}")
    
    train_df = pd.read_csv(train_path, header=None, names=NSL_KDD_COLUMNS)
    test_df = pd.read_csv(test_path, header=None, names=NSL_KDD_COLUMNS) if os.path.exists(test_path) else None
    
    # Map attack types to 5 high-level classes
    train_df["attack_category"] = train_df["attack"].apply(lambda a: ATTACK_CATEGORY_MAP.get(str(a).lower(), "DoS"))
    if test_df is not None:
        test_df["attack_category"] = test_df["attack"].apply(lambda a: ATTACK_CATEGORY_MAP.get(str(a).lower(), "DoS"))
    
    if sample_size and len(train_df) > sample_size:
        train_df = train_df.sample(n=sample_size, random_state=42).reset_index(drop=True)
        
    return train_df, test_df

if __name__ == "__main__":
    ensure_dataset_available()
    train_df, test_df = load_nsl_kdd(sample_size=1000)
    print(f"Loaded Train: {train_df.shape}, Categories: {train_df['attack_category'].value_counts().to_dict()}")
