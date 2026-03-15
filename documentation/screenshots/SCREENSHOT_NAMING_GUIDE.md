# Screenshot Naming & Reference Guide
## AI-Powered Network Intrusion Detection System

**Date:** March 15, 2026  
**Purpose:** Complete guide for naming, capturing, and referencing all documentation screenshots  
**Screenshot Location:** `documentation/screenshots/`

---

## Part 1: Screenshot Naming Convention

### Format
```
[COMPONENT]_[ACTION]_[STATE].png
```

### Components
- **BACKEND** = PowerShell terminal showing backend startup
- **FRONTEND** = Browser showing Next.js dashboard
- **KALI** = Kali Linux terminal for attack execution
- **ALERT** = Dashboard alert/forensic details
- **SYSTEM** = System status or configuration page

### Actions
- **STARTUP** = Application initialization
- **LOGIN** = Authentication screen
- **INITIAL** = First load state
- **ACTIVE** = During operation
- **DETECTED** = After attack detected
- **EXECUTION** = Attack tool running
- **COMMAND** = Before executing command
- **COMPLETE** = After completion
- **BENIGN** = Normal traffic (no alert)
- **DETAIL** = Expanded/detailed view

### States
- **OK** = Healthy/running
- **MONITORING** = Active monitoring
- **IDLE** = Waiting/inactive
- **ALERT** = Alert generated
- **FORENSICS** = Detailed forensic report
- **PORTSCAN** = PortScan attack type
- **BRUTEFORCE** = Brute force attack
- **UDPFLOOD** = UDP flood attack
- **NOUPDATE** = No update/no change

---

## Part 2: Complete Screenshot List with Naming

### **SECTION 1: Application Startup**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 1 | `BACKEND_STARTUP_OK.png` | PowerShell Terminal 1 | `python -m uvicorn api.main:app --reload` output | Wait for "Uvicorn running on http://127.0.0.1:8000" |
| 2 | `FRONTEND_STARTUP_OK.png` | PowerShell Terminal 2 | `npm run dev` output | Wait for "ready on http://localhost:3000" |

### **SECTION 2: Dashboard Authentication**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 3 | `FRONTEND_LOGIN_INITIAL.png` | Browser http://localhost:3000 | Login form with empty fields | Fields: Username, Password, Login button |
| 4 | `FRONTEND_LOGIN_CREDENTIALS.png` | Browser http://localhost:3000 | Login form with filled fields | Username: `admin`, Password: `ids2024` (filled in) |

### **SECTION 3: Dashboard Initial State**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 5 | `FRONTEND_DASHBOARD_INITIAL.png` | Browser (after login) | Main dashboard, monitoring IDLE | Shows 🔵 IDLE indicator, total alerts: 0 |
| 6 | `FRONTEND_CONTROL_PANEL.png` | Browser dashboard | Control panel section | Shows [Start Monitoring] [Stop] [Quick Capture] buttons |
| 7 | `FRONTEND_SYSTEM_STATUS.png` | Browser dashboard | System status display | Backend: Connected, ML Model: Loaded, Network: Active |

### **SECTION 4: PortScan Attack Test**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 8 | `FRONTEND_MONITORING_ACTIVE.png` | Browser dashboard | Dashboard with monitoring started | Shows 🔴 ACTIVE (red) indicator button changed to [Stop] |
| 9 | `KALI_NMAP_COMMAND_READY.png` | Kali Terminal | Terminal with nmap command typed | Command ready to execute: `sudo nmap -sS -p 1-500 -T4 192.168.56.1` |
| 10 | `KALI_NMAP_EXECUTION_PROGRESS.png` | Kali Terminal | nmap scan running | Show mid-scan output with packet counts |
| 11 | `KALI_NMAP_EXECUTION_COMPLETE.png` | Kali Terminal | nmap scan completion | Show final summary: ports scanned, hosts up, completion time |
| 12 | `FRONTEND_ALERT_PORTSCAN_GENERATED.png` | Browser dashboard | PortScan alert appears | Alert row visible in Recent Alerts list |
| 13 | `ALERT_PORTSCAN_DETAIL_FORENSICS.png` | Browser dashboard | Expanded alert view | Full forensic report: type, severity, ports, methodology |

### **SECTION 5: Normal Traffic (BENIGN) Test**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 14 | `KALI_PING_COMMAND_READY.png` | Kali Terminal | Terminal with ping command typed | Command: `ping -c 10 192.168.56.1` |
| 15 | `KALI_PING_EXECUTION_OUTPUT.png` | Kali Terminal | ping command output | Show all 10 ICMP packets, responses, success rate |
| 16 | `FRONTEND_BENIGN_NO_ALERTS.png` | Browser dashboard | Dashboard during/after ping | Monitoring still ACTIVE, but NO new alerts |

### **SECTION 6: SSH Brute Force Test (Optional)**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 17 | `KALI_HYDRA_COMMAND_READY.png` | Kali Terminal | Terminal with hydra command | Command: `hydra -l admin -P /tmp/passwords.txt ssh://192.168.56.1` |
| 18 | `KALI_HYDRA_EXECUTION_PROGRESS.png` | Kali Terminal | hydra running with attempts | Show password attempts, denied/accepted |
| 19 | `FRONTEND_ALERT_BRUTEFORCE_DETECTED.png` | Browser dashboard | SSH-Patator alert | Alert for brute force attempt |
| 20 | `ALERT_BRUTEFORCE_DETAIL_FORENSICS.png` | Browser dashboard | Expanded brute force alert | Forensic details of SSH attack |

### **SECTION 7: UDP Flood Test (Optional)**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 21 | `KALI_HPING3_COMMAND_READY.png` | Kali Terminal | Terminal with hping3 command | Command: `sudo hping3 -2 -p 53 --flood 192.168.56.1` |
| 22 | `KALI_HPING3_EXECUTION_PROGRESS.png` | Kali Terminal | hping3 flooding in progress | Show packet rate, statistics output |
| 23 | `FRONTEND_ALERT_UDPFLOOD_DETECTED.png` | Browser dashboard | UDP-Flood alert appears | Alert showing UDP flood classification |
| 24 | `ALERT_UDPFLOOD_DETAIL_FORENSICS.png` | Browser dashboard | Expanded UDP flood alert | Full forensic analysis of flood attack |

### **SECTION 8: System Shutdown**

| # | Screenshot Name | Source | What to Show | Notes |
|---|-----------------|--------|------------|-------|
| 25 | `FRONTEND_MONITORING_STOPPED.png` | Browser dashboard | Click [Stop Monitoring] | Shows 🔵 IDLE, counters frozen |
| 26 | `FRONTEND_FINAL_DASHBOARD_STATE.png` | Browser dashboard | Final dashboard summary | Total alerts generated, final statistics |

---

## Part 3: Folder Structure

```
documentation/
├── screenshots/
│   ├── 01_Startup/
│   │   ├── BACKEND_STARTUP_OK.png
│   │   └── FRONTEND_STARTUP_OK.png
│   ├── 02_Authentication/
│   │   ├── FRONTEND_LOGIN_INITIAL.png
│   │   └── FRONTEND_LOGIN_CREDENTIALS.png
│   ├── 03_Dashboard_Initial/
│   │   ├── FRONTEND_DASHBOARD_INITIAL.png
│   │   ├── FRONTEND_CONTROL_PANEL.png
│   │   └── FRONTEND_SYSTEM_STATUS.png
│   ├── 04_PortScan_Test/
│   │   ├── FRONTEND_MONITORING_ACTIVE.png
│   │   ├── KALI_NMAP_COMMAND_READY.png
│   │   ├── KALI_NMAP_EXECUTION_PROGRESS.png
│   │   ├── KALI_NMAP_EXECUTION_COMPLETE.png
│   │   ├── FRONTEND_ALERT_PORTSCAN_GENERATED.png
│   │   └── ALERT_PORTSCAN_DETAIL_FORENSICS.png
│   ├── 05_BENIGN_Traffic_Test/
│   │   ├── KALI_PING_COMMAND_READY.png
│   │   ├── KALI_PING_EXECUTION_OUTPUT.png
│   │   └── FRONTEND_BENIGN_NO_ALERTS.png
│   ├── 06_SSH_BruteForce_Test/
│   │   ├── KALI_HYDRA_COMMAND_READY.png
│   │   ├── KALI_HYDRA_EXECUTION_PROGRESS.png
│   │   ├── FRONTEND_ALERT_BRUTEFORCE_DETECTED.png
│   │   └── ALERT_BRUTEFORCE_DETAIL_FORENSICS.png
│   ├── 07_UDP_Flood_Test/
│   │   ├── KALI_HPING3_COMMAND_READY.png
│   │   ├── KALI_HPING3_EXECUTION_PROGRESS.png
│   │   ├── FRONTEND_ALERT_UDPFLOOD_DETECTED.png
│   │   └── ALERT_UDPFLOOD_DETAIL_FORENSICS.png
│   └── 08_Shutdown/
│       ├── FRONTEND_MONITORING_STOPPED.png
│       └── FRONTEND_FINAL_DASHBOARD_STATE.png
└── SCREENSHOT_NAMING_GUIDE.md (this file)
```

---

## Part 4: Where Each Screenshot Goes in Documentation

### Chapter 4: System Analysis and Design

**Section 4.6.1: Dashboard Interface - Login Page**
- **Image ref:** `![Screenshot: Login Page](screenshots/02_Authentication/FRONTEND_LOGIN_INITIAL.png)`
- **Shows:** Empty login form
- **Caption:** "Figure 4.2: Network IDS System Login Interface"

**Section 4.6.1: Dashboard Interface - Main Dashboard**
- **Image ref:** `![Screenshot: Dashboard Initial](screenshots/03_Dashboard_Initial/FRONTEND_DASHBOARD_INITIAL.png)`
- **Shows:** Dashboard with IDLE status
- **Caption:** "Figure 4.3: Main Dashboard - Initial State (No Monitoring)"

**Section 4.6.3: Monitoring Control Panel**
- **Image ref:** `![Screenshot: Control Panel](screenshots/03_Dashboard_Initial/FRONTEND_CONTROL_PANEL.png)`
- **Shows:** Start/Stop buttons and live statistics
- **Caption:** "Figure 4.4: Dashboard Control Panel with Monitoring Controls"

**Section 4.6.4: System Status Page**
- **Image ref:** `![Screenshot: System Status](screenshots/03_Dashboard_Initial/FRONTEND_SYSTEM_STATUS.png)`
- **Shows:** Backend, ML model, network interface status
- **Caption:** "Figure 4.5: System Status Display - Component Health Check"

---

### Chapter 5: Implementation & Testing

**Section 5.1: Testing Methodologies - Backend Startup**
- **Image ref:** `![Screenshot: Backend Startup](screenshots/01_Startup/BACKEND_STARTUP_OK.png)`
- **Shows:** Uvicorn initialization and running confirmation
- **Caption:** "Figure 5.1: Backend API Server Startup - FastAPI/Uvicorn Console Output"

**Section 5.1: Testing Methodologies - Frontend Startup**
- **Image ref:** `![Screenshot: Frontend Startup](screenshots/01_Startup/FRONTEND_STARTUP_OK.png)`
- **Shows:** Next.js development server ready
- **Caption:** "Figure 5.2: Frontend Development Server Startup - Next.js Console Output"

**Section 5.2.1: PortScan Detection - Monitoring Activated**
- **Image ref:** `![Screenshot: Monitoring Active](screenshots/04_PortScan_Test/FRONTEND_MONITORING_ACTIVE.png)`
- **Shows:** Dashboard with 🔴 ACTIVE indicator
- **Caption:** "Figure 5.3: Dashboard with Continuous Monitoring Activated"

**Section 5.2.1: PortScan Detection - nmap Command**
- **Image ref:** `![Screenshot: nmap Ready](screenshots/04_PortScan_Test/KALI_NMAP_COMMAND_READY.png)`
- **Shows:** Kali terminal with nmap command typed
- **Caption:** "Figure 5.4: PortScan Attack Preparation - nmap Command Ready to Execute"

**Section 5.2.1: PortScan Detection - nmap Execution**
- **Image ref:** `![Screenshot: nmap Running](screenshots/04_PortScan_Test/KALI_NMAP_EXECUTION_PROGRESS.png)`
- **Shows:** nmap scan in progress
- **Caption:** "Figure 5.5: PortScan Attack Execution - nmap Scan in Progress"

**Section 5.2.1: PortScan Detection - nmap Complete**
- **Image ref:** `![Screenshot: nmap Done](screenshots/04_PortScan_Test/KALI_NMAP_EXECUTION_COMPLETE.png)`
- **Shows:** nmap scan completed with summary
- **Caption:** "Figure 5.6: PortScan Attack Completion - Final Scan Summary"

**Section 5.2.1: PortScan Detection - Alert Generated**
- **Image ref:** `![Screenshot: Alert Generated](screenshots/04_PortScan_Test/FRONTEND_ALERT_PORTSCAN_GENERATED.png)`
- **Shows:** PortScan alert in dashboard
- **Caption:** "Figure 5.7: Alert Generation - PortScan Attack Detected on Dashboard"

**Section 5.2.1: PortScan Detection - Forensic Details**
- **Image ref:** `![Screenshot: Forensic Details](screenshots/04_PortScan_Test/ALERT_PORTSCAN_DETAIL_FORENSICS.png)`
- **Shows:** Expanded forensic report
- **Caption:** "Figure 5.8: Forensic Analysis - Detailed PortScan Report with Methodology"

**Section 5.2.4: BENIGN Traffic - Ping Command**
- **Image ref:** `![Screenshot: Ping Command](screenshots/05_BENIGN_Traffic_Test/KALI_PING_COMMAND_READY.png)`
- **Shows:** Ping command ready to execute
- **Caption:** "Figure 5.9: Normal Traffic Test - Ping Command Ready"

**Section 5.2.4: BENIGN Traffic - Ping Output**
- **Image ref:** `![Screenshot: Ping Output](screenshots/05_BENIGN_Traffic_Test/KALI_PING_EXECUTION_OUTPUT.png)`
- **Shows:** Ping execution with responses
- **Caption:** "Figure 5.10: Normal ICMP Traffic - Legitimate Network Communication"

**Section 5.2.4: BENIGN Traffic - No Alerts**
- **Image ref:** `![Screenshot: No Alerts](screenshots/05_BENIGN_Traffic_Test/FRONTEND_BENIGN_NO_ALERTS.png)`
- **Shows:** Dashboard with no alerts during normal traffic
- **Caption:** "Figure 5.11: BENIGN Classification - Dashboard Shows No False Alarms"

**Section 5.2.2: SSH Brute Force (Optional)**
- **Image ref (1):** `![Screenshot: Hydra Ready](screenshots/06_SSH_BruteForce_Test/KALI_HYDRA_COMMAND_READY.png)`
- **Shows:** Hydra command typed in Kali
- **Caption:** "Figure 5.12a: SSH Brute Force - Hydra Attack Preparation"

- **Image ref (2):** `![Screenshot: Brute Force Alert](screenshots/06_SSH_BruteForce_Test/FRONTEND_ALERT_BRUTEFORCE_DETECTED.png)`
- **Shows:** SSH-Patator alert on dashboard
- **Caption:** "Figure 5.12b: Brute Force Detection - SSH-Patator Alert"

**Section 5.2.3: UDP Flood (Optional)**
- **Image ref (1):** `![Screenshot: hping3 Ready](screenshots/07_UDP_Flood_Test/KALI_HPING3_COMMAND_READY.png)`
- **Shows:** hping3 command in Kali terminal
- **Caption:** "Figure 5.13a: UDP Flood Attack - hping3 Command Preparation"

- **Image ref (2):** `![Screenshot: UDP Flood Alert](screenshots/07_UDP_Flood_Test/FRONTEND_ALERT_UDPFLOOD_DETECTED.png)`
- **Shows:** UDP-Flood alert on dashboard
- **Caption:** "Figure 5.13b: UDP Flood Detection - Attack Alert on Dashboard"

---

## Part 5: Quick Reference for Capturing

### Checklist for Each Test

**PortScan Test (6 screenshots):**
- [ ] Start monitoring on dashboard
- [ ] Capture dashboard ACTIVE state
- [ ] Capture nmap command typed (Kali)
- [ ] Capture nmap running (progress)
- [ ] Capture nmap completed (summary)
- [ ] Capture alert on dashboard
- [ ] Capture expanded forensic report

**BENIGN Traffic Test (3 screenshots):**
- [ ] Capture ping command typed (Kali)
- [ ] Capture ping output (10 packets)
- [ ] Capture dashboard (no alerts generated)

**Brute Force Test (3 screenshots - optional):**
- [ ] Capture hydra command typed (Kali)
- [ ] Capture hydra execution (attempts shown)
- [ ] Capture alert on dashboard

**UDP Flood Test (3 screenshots - optional):**
- [ ] Capture hping3 command typed (Kali)
- [ ] Capture hping3 execution (flooding)
- [ ] Capture alert on dashboard

---

## Part 6: How to Create Screenshots

### Windows Host Screenshots (Browser)
```
Method 1: Windows Snipping Tool
- Press Windows Key + Shift + S
- Select area
- Save to documentation/screenshots/ folder
- Rename according to convention

Method 2: Print Screen
- Press Print Screen (full) or Alt+Print Screen (window)
- Open Paint
- Paste
- Crop as needed
- Save with proper name
```

### Kali Linux Terminal Screenshots
```
Method 1: scrot (already installed)
- scrot ~/Documents/screenshot.png
- Then move to Windows shared folder
- Rename according to convention

Method 2: GNOME Screenshot
- Press Print Screen
- Save location: shared folder
- Rename according to convention

Method 3: Manual Copy/Paste
- Select terminal text
- Copy
- Paste in text file
- Take screenshot of text file
```

### Browser Dashboard Screenshots
```
Best Practice:
- Maximize browser window
- Disable browser tabs if possible
- Navigate to exact location
- Use Snipping Tool to capture area
- Save with proper name
- Format: PNG (best for clarity)
```

---

## Part 7: File Naming Quick Reference

| # | Filename | Component | Action | State | Chapter | Section |
|---|----------|-----------|--------|-------|---------|---------|
| 1 | BACKEND_STARTUP_OK | BACKEND | STARTUP | OK | 5 | 5.1 |
| 2 | FRONTEND_STARTUP_OK | FRONTEND | STARTUP | OK | 5 | 5.1 |
| 3 | FRONTEND_LOGIN_INITIAL | FRONTEND | LOGIN | INITIAL | 4 | 4.6.1 |
| 4 | FRONTEND_LOGIN_CREDENTIALS | FRONTEND | LOGIN | CREDENTIALS | 4 | 4.6.1 |
| 5 | FRONTEND_DASHBOARD_INITIAL | FRONTEND | INITIAL | INITIAL | 4 | 4.6.1 |
| 6 | FRONTEND_CONTROL_PANEL | FRONTEND | CONTROL | PANEL | 4 | 4.6.3 |
| 7 | FRONTEND_SYSTEM_STATUS | FRONTEND | STATUS | OK | 4 | 4.6.4 |
| 8 | FRONTEND_MONITORING_ACTIVE | FRONTEND | ACTIVE | MONITORING | 5 | 5.2.1 |
| 9 | KALI_NMAP_COMMAND_READY | KALI | COMMAND | READY | 5 | 5.2.1 |
| 10 | KALI_NMAP_EXECUTION_PROGRESS | KALI | EXECUTION | PROGRESS | 5 | 5.2.1 |
| 11 | KALI_NMAP_EXECUTION_COMPLETE | KALI | EXECUTION | COMPLETE | 5 | 5.2.1 |
| 12 | FRONTEND_ALERT_PORTSCAN_GENERATED | FRONTEND | ALERT | PORTSCAN | 5 | 5.2.1 |
| 13 | ALERT_PORTSCAN_DETAIL_FORENSICS | ALERT | DETAIL | FORENSICS | 5 | 5.2.1 |
| 14 | KALI_PING_COMMAND_READY | KALI | COMMAND | READY | 5 | 5.2.4 |
| 15 | KALI_PING_EXECUTION_OUTPUT | KALI | EXECUTION | OUTPUT | 5 | 5.2.4 |
| 16 | FRONTEND_BENIGN_NO_ALERTS | FRONTEND | BENIGN | NOUPDATE | 5 | 5.2.4 |
| 17 | KALI_HYDRA_COMMAND_READY | KALI | COMMAND | READY | 5 | 5.2.2 |
| 18 | KALI_HYDRA_EXECUTION_PROGRESS | KALI | EXECUTION | PROGRESS | 5 | 5.2.2 |
| 19 | FRONTEND_ALERT_BRUTEFORCE_DETECTED | FRONTEND | ALERT | BRUTEFORCE | 5 | 5.2.2 |
| 20 | ALERT_BRUTEFORCE_DETAIL_FORENSICS | ALERT | DETAIL | FORENSICS | 5 | 5.2.2 |
| 21 | KALI_HPING3_COMMAND_READY | KALI | COMMAND | READY | 5 | 5.2.3 |
| 22 | KALI_HPING3_EXECUTION_PROGRESS | KALI | EXECUTION | PROGRESS | 5 | 5.2.3 |
| 23 | FRONTEND_ALERT_UDPFLOOD_DETECTED | FRONTEND | ALERT | UDPFLOOD | 5 | 5.2.3 |
| 24 | ALERT_UDPFLOOD_DETAIL_FORENSICS | ALERT | DETAIL | FORENSICS | 5 | 5.2.3 |
| 25 | FRONTEND_MONITORING_STOPPED | FRONTEND | STOPPED | IDLE | 5 | 5.4.3 |
| 26 | FRONTEND_FINAL_DASHBOARD_STATE | FRONTEND | FINAL | SUMMARY | 5 | 5.4.3 |

---

## Notes

- **Total Screenshots Required:** 26 (16 required, 10 optional for full testing)
- **Minimum for Documentation:** 16 (PortScan + BENIGN tests)
- **Recommended for Comprehensive:** 19 (+ SSH Brute Force)
- **Full Testing Suite:** 26 (+ UDP Flood)

- **Screenshot Locations in Documentation:** `./screenshots/` folder (relative path)
- **Markdown Syntax:** `![Description](screenshots/subfolder/FILENAME.png)`
- **Image Format:** PNG (recommended) or JPG (acceptable)
- **Resolution:** Capture at native resolution (don't downscale)

---

**Last Updated:** March 15, 2026  
**Status:** Ready for Screenshot Capture Phase

