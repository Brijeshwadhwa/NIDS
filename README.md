# NIDS

# 🔐 Network Intrusion Detection System (NIDS) using Python + Scapy

A real-time Network Intrusion Detection System (NIDS) built using Python, Scapy, and Flask with a web-based monitoring dashboard.

This project captures live network traffic, analyzes packets, detects suspicious activities using signature-based detection techniques, and displays alerts in a professional web interface.

---

## 🚀 Features

- Real-time packet sniffing using Scapy
- Signature-based intrusion detection
- Web-based dashboard (Flask)
- SQLite database logging
- Start/Stop packet capture from UI
- Live alert feed
- Protocol distribution monitoring
- Attack statistics overview

---

## 🛡️ Detected Attack Types

- SYN Flood Attack
- Port Scanning
- ICMP Flood
- ARP Spoofing
- Brute Force Simulation Detection

Each detected threat:
- Generates real-time alert
- Stores event in database
- Displays on dashboard

---

## 🏗️ Project Architecture


nids_project/
│
├── app.py
├── packet_sniffer.py
├── detection_engine.py
├── database.py
├── config.py
│
├── templates/
│ ├── index.html
│ ├── logs.html
│
├── static/
│ ├── style.css
│ ├── script.js
│
└── requirements.txt


---

## 🧠 Technologies Used

- Python 3
- Flask
- Scapy
- SQLite
- HTML / CSS / Bootstrap
- JavaScript (AJAX)

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/nids-project.git
cd nids-project

Install dependencies:

pip install -r requirements.txt

Run the application:

python app.py

Open in browser:

http://127.0.0.1:5000
⚠️ Important Note

Packet sniffing requires elevated privileges.

On Linux:

sudo python app.py

On Windows:
Run terminal as Administrator.

📊 How It Works

Scapy captures live network packets.

Packets are passed to detection engine.

Detection rules analyze traffic patterns.

Alerts are generated for suspicious activity.

Events are stored in SQLite database.

Flask dashboard displays real-time statistics.

🔍 Detection Approach

This project uses:

Signature-based detection

Traffic pattern analysis

Threshold-based anomaly checks

🎯 Project Objective

To design and implement a lightweight, real-time Network Intrusion Detection System capable of monitoring, analyzing, and alerting on suspicious network behavior using Python.

📌 Future Improvements

Machine learning-based anomaly detection

Automatic IP blocking (IPS functionality)

Real-time traffic visualization charts

Email/SMS alert notifications

Role-based authentication system

👨‍💻 Author

Your Name
Cybersecurity Student

⭐ If you found this project useful, consider giving it a star!

---

Now let’s prepare your LinkedIn post.

---

# 🔥 PROFESSIONAL LINKEDIN POST

Copy this and post it:

---

🚀 **Built a Real-Time Network Intrusion Detection System (NIDS) using Python**

I’m excited to share my latest cybersecurity project:

🔐 **Network Intrusion Detection System (NIDS)**  
Built using Python, Scapy, and Flask.

This system captures live network traffic, analyzes packets in real time, and detects suspicious activities through signature-based detection techniques.

### 🔍 Key Features:
- Real-time packet sniffing
- SYN Flood detection
- Port Scan detection
- ICMP Flood detection
- ARP Spoofing detection
- Brute-force attempt detection
- Web-based monitoring dashboard
- SQLite logging system

The system includes a professional web interface that allows starting/stopping traffic monitoring and viewing live alerts and statistics.

This project helped me strengthen my understanding of:
- Network protocols (TCP/IP, ARP, ICMP)
- Packet analysis
- Intrusion detection systems
- Security monitoring architecture
- Flask-based web development

Next, I plan to enhance it with anomaly-based detection and automated IP blocking.

GitHub Repository:
👉 [Add your GitHub link here]

#CyberSecurity #Python #NetworkSecurity #NIDS #Scapy #Flask #EthicalHacking #BlueTeam #SecurityEngineering

---

# 🎯 Resume Version (Short)

You can add this to your CV:

**Network Intrusion Detection System (NIDS)**  
Developed a real-time NIDS using Python, Scapy, and Flask capable of detecting SYN floods, port scans, ICMP floods, ARP spoofing, and brute-force attempts with live dashboard monitoring and SQLite-based logging.

---

If you want, I can also:

- Optimize your GitHub repository structure professionally
- Help you write a SECURITY.md
- Create a project banner image
- Write a technical blog version for Medium
- Help you prepare a demo explanation script
- Make your LinkedIn profile cybersecurity-optimized

Tell me what you want next 🔥
