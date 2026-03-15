# AI-Powered Network Intrusion Detection System (IDS)

A real-time network intrusion detection and breach analysis system powered by machine learning. This system monitors network traffic, detects anomalies, classifies attack types, and provides actionable security recommendations.

![IDS Dashboard](https://img.shields.io/badge/Status-Prototype-yellow) ![Python](https://img.shields.io/badge/Python-3.11-blue) ![Next.js](https://img.shields.io/badge/Next.js-16.0-black)

## 🚀 Features

- **Real-time Traffic Monitoring** - Captures and analyzes network packets using Scapy
- **ML-Based Anomaly Detection** - Uses Isolation Forest algorithm to detect unusual patterns
- **Attack Classification** - Identifies attack types (Port Scan, DDoS, Brute Force, etc.)
- **Interactive Dashboard** - Beautiful Next.js frontend with real-time updates
- **Breach Analysis** - Detailed forensic reports with recommendations
- **REST API** - FastAPI backend for seamless integration

## � Documentation Files

This project includes comprehensive documentation for academic submission:

- **[DOCUMENTATION_CHAPTERS_4-6.md](DOCUMENTATION_CHAPTERS_4-6.md)** - Complete final year project documentation including:
  - Chapter 4: System Design & Architecture
  - Chapter 5: Implementation & Testing (with CLI commands for nmap, hydra, hping3)
  - Chapter 6: Results & Conclusions
  - Ready for screenshots integration with markdown references

- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - Complete file inventory and project structure overview

- **[SCREENSHOT_NAMING_GUIDE.md](documentation/SCREENSHOT_NAMING_GUIDE.md)** - Screenshot organization guide with:
  - 26 screenshot filenames with naming convention
  - Folder structure (01_Startup, 02_Authentication, etc.)
  - Capture instructions for each screenshot
  - Mapping to documentation sections

- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Detailed installation instructions

- **[VM_GUIDE.md](VM_GUIDE.md)** - Virtual machine configuration guide

## �📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.11** - [Download here](https://www.python.org/downloads/)
- **Node.js 18+** - [Download here](https://nodejs.org/)
- **Npcap** (Windows) - [Download here](https://npcap.com/#download)
- **Git** - [Download here](https://git-scm.com/)

## 🛠️ Installation & Setup

### Step 1: Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/network-ids-system.git
cd network-ids-system
```

### Step 2: Backend Setup (Python)
```bash
# Navigate to backend folder
cd backend

# Create virtual environment with Python 3.11
py -3.11 -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Train the ML model (IMPORTANT - Do this first!)
python test_ml.py
```

⚠️ **Important:** The `test_ml.py` script will capture network traffic to train the anomaly detection model. This takes about 2 minutes.

### Step 3: Frontend Setup (Next.js)

Open a **NEW terminal** and:
```bash
# Navigate to frontend folder
cd frontend

# Install dependencies
npm install

# This will take 1-2 minutes
```

## 🚀 Running the System

You need **TWO terminals running simultaneously**:

### Terminal 1: Start the Backend API
```bash
cd backend
venv\Scripts\activate  # On Windows
python run.py
```

✅ You should see: `Uvicorn running on http://127.0.0.1:8000`

⚠️ **Note:** Use `python run.py` instead of `uvicorn` - this script cleaner terminal output without personal file paths.

### Terminal 2: Start the Frontend Dashboard
```bash
cd frontend
npm run dev
```

✅ You should see: `Local: http://localhost:3000`

## 🎯 Using the Dashboard

1. Open your browser and go to: **http://localhost:3000**
2. Click **"Capture Traffic"** to analyze network packets
3. View real-time alerts and statistics
4. Monitor attack types and severity levels

## 📊 System Architecture
```
┌─────────────────┐         REST API        ┌──────────────────┐
│   Next.js       │ ◄─────────────────────► │   FastAPI        │
│   Dashboard     │   (localhost:3000)      │   Backend        │
│                 │                          │                  │
│ - Stats Display │                          │ - Traffic Monitor│
│ - Alert Manager │                          │ - ML Detection   │
│ - Charts        │                          │ - Classifier     │
└─────────────────┘                          └──────────────────┘
                                                     │
                                                     ▼
                                             ┌──────────────────┐
                                             │   Network        │
                                             │   Interface      │
                                             └──────────────────┘
```

## 🔧 Troubleshooting

### "Failed to fetch" error on dashboard
- Ensure the Python API is running on port 8000
- Check that both terminals are active
- Verify the backend started without errors

### "Need administrator privileges" error
- Close VS Code
- Right-click VS Code → "Run as Administrator"
- Try again

### No packets being captured
- Install Npcap: https://npcap.com/#download
- Make sure you have network connectivity
- Try opening a browser and visiting websites to generate traffic

### Model not trained
- Run `python test_ml.py` in the backend folder first
- This creates the `models/anomaly_detector.pkl` file
- Without this, detection won't work

## 📁 Project Structure
```
network-ids-system/
├── backend/
│   ├── capture/              # Network packet capture
│   │   └── traffic_monitor.py
│   ├── ml/                   # Machine learning models
│   │   ├── feature_extractor.py
│   │   ├── detector.py
│   │   └── classifier.py
│   ├── api/                  # REST API
│   │   └── main.py
│   ├── config/               # Configuration
│   │   └── settings.py
│   ├── models/               # Trained ML models
│   ├── data/                 # Captured traffic logs
│   ├── requirements.txt      # Python dependencies
│   ├── test_ml.py           # ML training script
│   └── ids_system.py        # Main IDS system
│
├── frontend/
│   ├── app/
│   │   ├── page.js          # Main dashboard
│   │   ├── layout.js
│   │   └── globals.css
│   ├── next.config.js
│   └── package.json
│
├── .gitignore
└── README.md
```

## 🎓 Technologies Used

**Backend:**
- Python 3.11
- Scapy (packet capture)
- scikit-learn (ML)
- FastAPI (REST API)
- Pandas & NumPy (data processing)

**Frontend:**
- Next.js 16
- React 19
- Tailwind CSS
- Recharts (visualizations)
- Lucide React (icons)

## 🔐 Security Notes

- This system requires **administrator/root privileges** to capture network packets
- Only use on networks you own or have permission to monitor
- The system is a **prototype** for educational/demonstration purposes
- Do not deploy to production without proper security hardening

## 📝 License

This project is for academic/demonstration purposes.

## 👥 Contributors

- [Your Name]
- [Team Members]

## 🐛 Known Issues

- System must run with administrator privileges on Windows
- Capturing stops if network adapter changes
- Dashboard requires manual refresh if API restarts

## 📧 Contact

For questions or issues, please contact: [your-email@example.com]

---

**⭐ If you find this project useful, please give it a star!**