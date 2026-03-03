<p align="center">
  <img src="https://img.shields.io/badge/C++-17-blue?logo=cplusplus&logoColor=white" alt="C++17">
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey?logo=linux&logoColor=white" alt="Linux">

  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Active">
</p>

<h1 align="center">🛡️ IDS Guard — Network Intrusion Detection System</h1>

<p align="center">
  A real-time <strong>Network Intrusion Detection System</strong> built in C++ with an embedded HTTP server and a modern glassmorphism web dashboard. Captures live network traffic, detects attacks using rule-based and behavioral analysis, and presents everything through a stunning browser-based GUI.
</p>

---

## ✨ Features

| Category | Details |
|---|---|
| **Live Packet Capture** | Sniff network traffic in real-time on any interface using `libpcap` |
| **Attack Detection** | SYN Flood detection, Port Scan detection, Traffic Burst analysis |
| **Custom Rules Engine** | Define keyword-based detection rules with severity levels (CRITICAL → INFO) |
| **Threat Intelligence** | Adaptive scoring — mark events as true threats or false alarms to improve accuracy |
| **PCAP Replay** | Upload `.pcap` capture files and analyze them offline |
| **Monitored IPs** | Maintain a watchlist of IPs with notes for targeted monitoring |
| **Analytics Dashboard** | Interactive charts for top talkers (IPs) and most targeted ports |
| **CSV Export** | Export captured events to CSV for external analysis |
| **Embedded Web Server** | Built-in HTTP server on port `8080` — no external web server needed |

---

## 🖥️ Dashboard Preview

The web dashboard features a **dark glassmorphism UI** with:

- 📊 Real-time statistics (total packets, capture runtime, threat indicators)
- 📈 Interactive bar charts for top source IPs and targeted ports
- 🎛️ Packet capture controls with interface selector
- 📋 Live event stream with severity-based color coding
- 🔍 Filtering by IP, severity level, and verification status
- 👁️ Monitored IP management modal
- 📜 Detection rules management modal
- 📤 PCAP file upload for offline analysis

---

## 🛠️ Tech Stack

- **Backend:** C++17 with POSIX threads
- **Packet Capture:** `libpcap`
- **Web Server:** Custom embedded HTTP server (sockets)
- **Frontend:** HTML5 + CSS3 + Vanilla JavaScript
- **Charts:** [Chart.js](https://www.chartjs.org/)
- **Typography:** [Plus Jakarta Sans](https://fonts.google.com/specimen/Plus+Jakarta+Sans)

---

## 📋 Prerequisites

- **Linux** (Ubuntu/Debian recommended)
- **g++** (with C++17 support)
- **libpcap** development headers

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install g++ libpcap-dev
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/mehraniqbalgp/DSA-IDS-Project.git
cd DSA-IDS-Project
```

### 2. Compile

```bash
# Compile the integrated version (with web dashboard)
g++ -std=c++17 -o ids_integrated ids_integrated.cpp -lpcap -lpthread

# Compile the CLI-only version
g++ -std=c++17 -o ids ids.cpp -lpcap -lpthread
```

### 3. Run

```bash
# Run the integrated version (requires root for packet capture)
sudo ./ids_integrated
```

### 4. Open the Dashboard

Navigate to **[http://localhost:8080](http://localhost:8080)** in your browser.

---

## 📁 Project Structure

```
DSA-IDS-Project/
├── ids_integrated.cpp     # Main source — IDS engine + embedded web server
├── ids.cpp                # CLI-only version of the IDS engine
├── dashboard.html         # Web dashboard (served by embedded server)
├── rules.txt              # Active detection rules
├── rulesbook.txt          # Extended rulebook with 90+ signatures
├── monitored_ips.txt      # Watchlisted IP addresses
├── intelligence.dat       # Persistent threat intelligence data
├── result.csv             # Captured events export
├── monitored_report.csv   # Monitored IP report
├── report.txt             # Detailed text report
└── README.md              # You are here
```

---

## 📜 Detection Rules

Rules follow a simple `keyword = severity` format:

```
# Authentication Events
failed login = MEDIUM
multiple failed login = HIGH
brute force = CRITICAL

# Network Attacks
port scan = HIGH
syn flood = CRITICAL
ddos attack = CRITICAL

# Web Attacks
sql injection = CRITICAL
xss attack = CRITICAL
command injection = CRITICAL
```

The full rulebook (`rulesbook.txt`) contains **90+ detection signatures** across categories:
- 🔐 Authentication Events
- ⬆️ Privilege Escalation
- 📂 File System Access
- 🌐 Network Attacks
- 🕸️ Web Attacks
- 🦠 Malware Signatures
- 📤 Data Exfiltration
- ⚙️ System Events
- 🔎 Reconnaissance
- 🚨 Suspicious Behavior

---

## 🔧 How It Works

```
                    ┌──────────────┐
                    │  Network     │
                    │  Interface   │
                    └──────┬───────┘
                           │ libpcap
                    ┌──────▼───────┐
                    │  Packet      │
                    │  Capture     │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼──────┐ ┌──▼──────────┐
       │ Rule-Based  │ │Behavioral│ │ Monitored   │
       │ Matching    │ │Analysis  │ │ IP Check    │
       └──────┬──────┘ └──┬──────┘ └──┬──────────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼───────┐
                    │  Event       │
                    │  Generation  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼──────┐ ┌──▼──────────┐
       │ Web Dashboard│ │CSV Export│ │ Intelligence │
       │ (Port 8080) │ │         │ │ Storage      │
       └─────────────┘ └─────────┘ └──────────────┘
```

1. **Packet Capture** — Uses `libpcap` to capture raw packets from a selected network interface
2. **Protocol Parsing** — Extracts IP headers, TCP/UDP ports, and flags
3. **Rule Matching** — Compares packet data against defined rules and keywords
4. **Behavioral Analysis** — Detects SYN floods, port scans, and traffic bursts using connection tracking
5. **Threat Scoring** — Assigns severity with adaptive scoring based on user feedback
6. **Dashboard Display** — Serves results via the embedded web server to the browser dashboard

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---



## 👤 Author

**Mehran Iqbal**  
🔗 GitHub: [@mehraniqbalgp](https://github.com/mehraniqbalgp)  
💼 LinkedIn: [mehraniqbalgp](https://linkedin.com/in/mehraniqbalgp)  
🌐 Website: [retrax.co](https://retrax.co)

---

<p align="center">
  Made with ❤️ for network security
</p>
