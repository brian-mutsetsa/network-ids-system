# Basic configuration for the IDS system

# Network settings
NETWORK_INTERFACE = None  # None = auto-detect, or specify like "Ethernet" or "Wi-Fi"
PACKET_COUNT = 100  # How many packets to capture at once

# File paths
DATA_FOLDER = "data"
MODELS_FOLDER = "models"

# Detection thresholds (we'll use these later)
ANOMALY_THRESHOLD = 0.7
ALERT_THRESHOLD = 0.8

print("✓ Configuration loaded successfully")