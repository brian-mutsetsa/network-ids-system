# Network IDS System - Complete Project Structure

This document provides a comprehensive overview of all files and directories in the Network Intrusion Detection System project.

## 📁 Directory Tree

```
network-ids-system/
│
├── README.md                              # Main project overview and quickstart guide
├── PROJECT_STATUS.md                      # Current status, progress, and next steps
├── SETUP_GUIDE.md                         # Detailed installation and setup instructions
├── VM_GUIDE.md                            # Virtual machine configuration guide
├── DOCUMENTATION_CHAPTERS_4-6.md         # Final year project documentation (Chapters 4-6)
├── PROJECT_STRUCTURE.md                   # This file - Complete file inventory
├── .gitignore                             # Git ignore patterns
├── package-lock.json                      # Frontend npm lock file
│
├── backend/                               # Python FastAPI Backend
│   ├── run.py                             # Startup script (use this instead of uvicorn command)
│   ├── requirements.txt                   # Python dependencies
│   ├── api/
│   │   ├── main.py                        # FastAPI application & REST endpoints
│   │   └── main.py.backup                 # Backup of original main.py
│   ├── capture/
│   │   ├── traffic_monitor.py             # Network packet capture using Scapy
│   │   └── __pycache__/                   # Python cache
│   ├── ml/
│   │   ├── feature_extractor.py           # Network feature extraction (32 features)
│   │   ├── detector.py                    # Anomaly detection (Isolation Forest)
│   │   ├── classifier.py                  # Attack classification (Random Forest)
│   │   ├── trained_classifier.py          # Pre-trained ML models
│   │   └── __pycache__/                   # Python cache
│   ├── config/
│   │   ├── settings.py                    # Configuration settings
│   │   └── __pycache__/                   # Python cache
│   ├── database/                          # Database storage (empty, reserved for future)
│   ├── models/                            # Trained ML models
│   │   ├── anomaly_detector.pkl           # Isolation Forest model
│   │   └── classifier_model.pkl           # Random Forest classifier
│   ├── dataset/                           # CIC-IDS2017 dataset
│   │   ├── *.pcap_ISCX.csv                # Network traffic CSV files (6+ files)
│   │   └── CSVs/
│   │       └── zip-files/                 # Compressed dataset backups
│   ├── data/
│   │   ├── alerts_20251115.txt            # Sample alert logs
│   │   └── test_capture.txt               # Test capture data
│   ├── analysis/
│   │   ├── breach_analyzer.py             # Breach analysis and forensics
│   │   └── __pycache__/                   # Python cache
│   │
│   ├── [Training & Testing Scripts]
│   ├── analyze_cic_better.py              # CIC dataset analysis script
│   ├── debug_capture.py                   # Network capture debugging
│   ├── explore_cic_csv.py                 # Dataset exploration
│   ├── test_monitor.py                    # Traffic monitor tests
│   ├── test_ml.py                         # ML model training & testing
│   ├── test_ml_detection.py               # Detection system testing
│   ├── test_pure_ml.py                    # Pure ML classification tests
│   ├── train_classifier.py                # Classifier training script
│   ├── train_diverse_attacks.py           # Diverse attack training
│   ├── train_diverse_attacks_slow.py      # Slow diverse attack training
│   ├── train_final_integrated.py          # Final integrated model training
│   ├── train_hybrid_cic_virtualbox.py     # Hybrid CIC+VirtualBox training
│   ├── train_hybrid_corrected.py          # Corrected hybrid training
│   ├── train_network_model.py             # Network model specific training
│   └── ids_system.py                      # Standalone IDS system
│
├── frontend/                              # Next.js React Frontend
│   ├── package.json                       # Frontend dependencies
│   ├── package-lock.json                  # npm lock file
│   ├── next.config.js                     # Next.js configuration
│   ├── next.config.mjs                    # Next.js config (ES modules)
│   ├── jsconfig.json                      # JavaScript configuration
│   ├── postcss.config.mjs                 # PostCSS configuration
│   ├── README.md                          # Frontend-specific readme
│   │
│   ├── app/
│   │   ├── layout.js                      # Root layout component
│   │   ├── page.js                        # Home page
│   │   ├── globals.css                    # Global styling
│   │   │
│   │   ├── login/
│   │   │   └── page.js                    # Login page component
│   │   │
│   │   └── breach-analysis/
│   │       └── [id]/
│   │           └── page.js                # Dynamic breach analysis page
│   │
│   ├── public/
│   │   └── [Static assets]                # Logos, images, fonts
│   │
│   ├── node_modules/                      # Installed dependencies (not in git)
│   └── .next/                             # Build output (not in git)
│
└── documentation/                         # Project documentation folder
    ├── SCREENSHOT_NAMING_GUIDE.md         # Screenshot naming convention guide
    └── screenshots/                       # Screenshot storage (for final project)
        ├── 01_Startup/
        ├── 02_Authentication/
        ├── 03_Dashboard_Initial/
        ├── 04_PortScan_Test/
        ├── 05_BENIGN_Traffic_Test/
        ├── 06_SSH_BruteForce_Test/
        ├── 07_UDP_Flood_Test/
        └── 08_Shutdown/
```

---

## 📄 Key Files Description

### Root Directory Files

| File | Purpose |
|------|---------|
| `README.md` | Main project overview, quickstart guide, troubleshooting |
| `PROJECT_STATUS.md` | Current development status and progress tracking |
| `SETUP_GUIDE.md` | Step-by-step installation and configuration guide |
| `VM_GUIDE.md` | Virtual machine setup for testing environments |
| `DOCUMENTATION_CHAPTERS_4-6.md` | **Complete final year project documentation** with system design, implementation, testing procedures, and results |
| `PROJECT_STRUCTURE.md` | This file - comprehensive file inventory |

### Backend Files

#### API & Configuration
| File | Purpose |
|------|---------|
| `backend/run.py` | **NEW:** Startup script that sanitizes file paths in logs |
| `backend/api/main.py` | FastAPI application with REST endpoints for IDS system |
| `backend/config/settings.py` | Configuration parameters (ports, thresholds, ML settings) |
| `backend/requirements.txt` | Python package dependencies |

#### Network Capture & Monitoring
| File | Purpose |
|------|---------|
| `backend/capture/traffic_monitor.py` | Real-time network packet capture using Scapy |
| `backend/debug_capture.py` | Debugging utilities for packet capture |
| `backend/test_monitor.py` | Unit tests for traffic monitoring |

#### Machine Learning
| File | Purpose |
|------|---------|
| `backend/ml/feature_extractor.py` | Extracts 32 network features from packets |
| `backend/ml/detector.py` | Isolation Forest anomaly detection |
| `backend/ml/classifier.py` | Random Forest attack classification |
| `backend/ml/trained_classifier.py` | Pre-trained ML models (99.99% accuracy) |

#### Analysis & Forensics
| File | Purpose |
|------|---------|
| `backend/analysis/breach_analyzer.py` | Detailed forensic analysis and recommendations |

#### Training & Testing Scripts
| File | Purpose |
|------|---------|
| `backend/test_ml.py` | Primary ML model training and validation |
| `backend/test_pure_ml.py` | Pure ML classification tests |
| `backend/test_ml_detection.py` | Detection system testing |
| `backend/train_classifier.py` | Classifier-specific training |
| `backend/train_diverse_attacks.py` | Multi-attack scenario training |
| `backend/train_hybrid_cic_virtualbox.py` | Hybrid CIC + VirtualBox training |
| `backend/train_final_integrated.py` | Final integrated model |
| `backend/analyze_cic_better.py` | CIC dataset analysis |
| `backend/explore_cic_csv.py` | Dataset exploration utilities |

### Frontend Files

| File | Purpose |
|------|---------|
| `frontend/app/page.js` | Main dashboard component |
| `frontend/app/login/page.js` | Login page with authentication |
| `frontend/app/layout.js` | Root layout and navigation |
| `frontend/app/globals.css` | Global CSS styling (Tailwind) |
| `frontend/app/breach-analysis/[id]/page.js` | Dynamic breach analysis detail page |
| `frontend/package.json` | Next.js and React dependencies |

---

## 🎯 Attack Detection Classes

The system detects 7 types of network attacks:

1. **BENIGN** - Normal traffic (no alert)
2. **PortScan** - Systematic port enumeration (nmap-based)
3. **DDoS** - Distributed Denial of Service (HTTP flooding)
4. **DoS** - Single-source Denial of Service
5. **SSH-Patator** - SSH credential brute force attack
6. **UDP-Flood** - UDP packet flooding (brute force variant)
7. **Infiltration** - Unauthorized access and malware

---

## 🔄 Testing Procedures (From DOCUMENTATION_CHAPTERS_4-6.md)

### Test Tools
- **nmap** - Port scanning attacks
- **hydra** - SSH brute force testing
- **hping3** - UDP flood generation
- **ping** - Benign traffic baseline

### Test Scenarios Documented
1. **PortScan Detection** - Detected in seconds using 6 screenshots
2. **BENIGN Traffic** - Baseline test with ping (3 screenshots)
3. **SSH Brute Force** - Optional advanced test (4 screenshots)
4. **UDP Flood** - Brute force variant test (4 screenshots)

### Screenshot Locations
All screenshots organized in: `documentation/screenshots/`

With naming convention: `[COMPONENT]_[ACTION]_[STATE].png`

Example: `KALI_NMAP_COMMAND_READY.png`, `FRONTEND_ALERT_PORTSCAN_GENERATED.png`

---

## 🚀 Running the System

### Quick Start
```bash
# Terminal 1: Backend
cd backend
python run.py

# Terminal 2: Frontend
cd frontend
npm run dev
```

### Access Dashboard
- **URL:** http://localhost:3000
- **Login:** admin / ids2024
- **API:** http://127.0.0.1:8000

---

## 📊 ML Model Performance

- **Training Accuracy:** 99.99% (Random Forest on CIC-IDS2017)
- **Real-world Detection:** 92-94% on actual network PortScan attacks
- **Model Type:** Ensemble (Isolation Forest + Random Forest)
- **Features:** 32 network features (packet size, duration, flags, etc.)

---

## 🔐 Network Configuration

### Testing Environment
- **Windows Host (IDS):** 192.168.56.1
- **Kali VM (Attacker):** 192.168.56.20
- **Network:** VirtualBox Host-Only (192.168.56.0/24)
- **Credentials:** admin / ids2024

---

## 📝 Dataset Information

The project uses the **CIC-IDS2017 dataset**:
- 8 CSV files with various attack scenarios
- Over 2.8 million network flow records
- Labeled with attack types and normal traffic
- Location: `backend/dataset/`

---

## 🛠️ Technologies Used

### Backend
- **Python 3.11**
- **FastAPI** - REST API framework
- **Scapy** - Network packet processing
- **scikit-learn** - Machine learning (Random Forest, Isolation Forest)
- **pandas** - Data processing
- **uvicorn** - ASGI server

### Frontend
- **Next.js 16** - React framework
- **React 19** - UI components
- **Tailwind CSS** - Styling
- **JavaScript ES6+**

### DevOps
- **VirtualBox** - Virtual machine platform
- **Git** - Version control
- **Npcap** - Windows packet capture

---

## 📜 Documentation Files

| File | Content |
|------|---------|
| `DOCUMENTATION_CHAPTERS_4-6.md` | **Main project documentation** - System Design (Ch 4), Implementation & Testing (Ch 5), Results (Ch 6) |
| `SCREENSHOT_NAMING_GUIDE.md` | Screenshot organization guide with 26 filenames and folder structure |
| `SETUP_GUIDE.md` | Installation and environment setup instructions |
| `VM_GUIDE.md` | Virtual machine configuration for testing |
| `PROJECT_STATUS.md` | Development status and progress |

---

## 🔒 .gitignore

The following are excluded from version control:
- `node_modules/` - Frontend dependencies
- `venv/` - Python virtual environment
- `.next/` - Next.js build output
- `__pycache__/` - Python cache
- Large dataset files
- `.env` files with secrets

---

## 📞 Key Information

### For Final Submission
- ✅ Complete Chapters 4-6 documentation in `DOCUMENTATION_CHAPTERS_4-6.md`
- ✅ Screenshot naming guide in `documentation/SCREENSHOT_NAMING_GUIDE.md`
- ✅ All source code in `backend/` and `frontend/`
- ✅ ML models trained and ready in `backend/models/`
- ✅ Test procedures with exact CLI commands documented

### To Add Screenshots
1. Follow naming convention in `SCREENSHOT_NAMING_GUIDE.md`
2. Place in `documentation/screenshots/` with proper folder structure
3. Markdown references already in `DOCUMENTATION_CHAPTERS_4-6.md`
4. No manual editing needed - just drop files in correct folders

---

## 📋 Last Updated

- **Date:** March 15, 2026
- **Latest Addition:** `backend/run.py` (path sanitization startup script)
- **Documentation Complete:** Chapters 4-6 with UDP Flood test procedures
- **Total Files:** 50+ (excluding node_modules and cache)

