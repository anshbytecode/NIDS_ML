import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
DB_PATH = os.path.join(BASE_DIR, "nids_events.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# 41 NSL-KDD feature names + attack + difficulty
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack", "difficulty_level"
]

# Mapping individual attack names to primary 5 classes
ATTACK_CATEGORY_MAP = {
    
    # Normal
    "normal": "Normal",
    
    # Denial of Service (DoS / DDoS)
    "neptune": "DoS", "smurf": "DoS", "back": "DoS", "teardrop": "DoS",
    "pod": "DoS", "land": "DoS", "apache2": "DoS", "udpstorm": "DoS",
    "processtable": "DoS", "mailbomb": "DoS", "worm": "DoS",
    
    # Surveillance / Probe
    "satan": "Probe", "ipsweep": "Probe", "portsweep": "Probe",
    "nmap": "Probe", "mscan": "Probe", "saint": "Probe",
    
    # Remote to Local (R2L / Brute Force / Unauthorized Access)
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L", "spy": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L", "named": "R2L",
    
    # User to Root (U2R / Privilege Escalation)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R",
    "perl": "U2R", "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R"
}

# MITRE ATT&CK Mapping
MITRE_MAPPING = {
    
    "DoS": {"tactic": "Impact", "technique_id": "T1499", "technique_name": "Endpoint Denial of Service"},
    "Probe": {"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery"},
    "R2L": {"tactic": "Initial Access", "technique_id": "T1110", "technique_name": "Brute Force / Credential Access"},
    "U2R": {"tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation"},
    "Normal": {"tactic": "N/A", "technique_id": "N/A", "technique_name": "Legitimate Traffic"},
    "Zero-Day / Anomaly": {"tactic": "Defense Evasion", "technique_id": "T0000", "technique_name": "Novel Behavioral Anomaly"}
}

# Threat Severity Levels
SEVERITY_MAPPING = {
    "Normal": "LOW",
    "Probe": "MEDIUM",
    "DoS": "HIGH",
    "R2L": "HIGH",
    "U2R": "CRITICAL",
    "Zero-Day / Anomaly": "CRITICAL"
}
