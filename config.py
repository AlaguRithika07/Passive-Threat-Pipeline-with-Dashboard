import os

WINDOW_SIZE_SECONDS = 10.0
SLIDE_INTERVAL_SECONDS = 2.0

# Performance Target
TARGET_THROUGHPUT_FPS = 5000  # Tested target: ~5,000 flows/sec sustained

# Threat Categories
THREAT_CLASSES = {
    0: "Normal",
    1: "Volumetric / Protocol DDoS",
    2: "Botnet C2 Beaconing",
    3: "DGA / DNS Tunnelling",
    4: "Encrypted Session Malware",
    5: "Reconnaissance & Port Scan",
    6: "Data Exfiltration"
}

ALERT_CONFIDENCE_THRESHOLD = 0.70