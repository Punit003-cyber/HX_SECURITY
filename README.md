# HX_SECURITY
HX is a modular cybersecurity system that collects system logs and browser data, scans them for threats using rule-based and API-driven detection, and visualizes insights on an interactive dashboard—empowering proactive threat detection and digital forensics in real time.
# HX Threat Intell Platform

**HX Threat Intell Platform** is an intelligent, modular cybersecurity system developed by **HX** to automate threat detection, analysis, and visualization across digital environments.  
It collects and scans endpoint and browser data, identifies suspicious behaviors or indicators of compromise (IOCs), and displays the findings through a clean, interactive dashboard.

---

## 🚀 Project Overview

Modern threats move fast — HX Threat Intell Platform moves faster.  
It automatically gathers logs, network events, and browser data from endpoints, scans them for malicious indicators using advanced rule-based logic and external reputation APIs, and presents the results in an intuitive dashboard designed for analysts and non-technical users alike.

---

## 🧩 Core Components

| Module | Purpose |
|--------|----------|
| **Log Collector** | Continuously collects system logs, process data, network events, and registry changes from endpoints. |
| **Scanner** | Analyzes logs and files for suspicious activity, cross-references with known IOCs, and generates structured alert data. |
| **Browser Data Extractor** | Safely extracts browser history, cookies, downloads, bookmarks, and password metadata for security auditing. |
| **Dashboard** | Displays analytics and results in a user-friendly web interface with charts, trends, and event summaries. |

---

## 🧠 How It Works

1. **Collect:** The platform collects system and browser logs from multiple sources in real time.  
2. **Scan:** Collected data is analyzed using rule-based detection and reputation checks.  
3. **Classify:** Findings are scored and categorized as safe or suspicious.  
4. **Visualize:** The dashboard transforms results into simple visuals, helping analysts identify trends or anomalies.  

---
<img width="1900" height="1033" alt="Screenshot 2025-10-22 211040" src="https://github.com/user-attachments/assets/2e870f12-77d1-42e5-920b-a2b6d68dcbb6" />

## 🧱 System Architecture
See the [ARCHITECTURE.md](ARCHITECTURE.md) file for a full explanation of data flow, modules, and design logic.

---

## 🔐 Privacy & Security
HX Threat Intell Platform is designed with **data privacy and integrity** in mind.  
It does not transmit sensitive personal data externally. All analysis happens locally, and integration with external APIs (like VirusTotal or Shodan) uses secure, user-provided API keys.

See [SECURITY_POLICY.md](SECURITY_POLICY.md) for details.

---

## 💡 Vision
Empower every security team — large or small — with a smart, automated, and visual way to understand and respond to cyber threats.

Read the [VISION.md](VISION.md) for the full roadmap.

---

## 📈 Status<img width="1882" height="729" alt="Screenshot 2025-10-22 211056" src="https://github.com/user-attachments/assets/ecd771b9-ea7a-496e-bb5a-1e3995ad4795" />

🚧 **Currently under internal evaluation.**  
Source code and proprietary algorithms are private, but documentation and vision are shared for educational and collaborative purposes.

---

## 🧰 Tech Stack
- Python (core logic and automation)
- Flask (dashboard interface)
- SQLite (lightweight local storage)
- Threading / Multiprocessing (concurrent collectors and scanners)
- JSON / Pandas (structured data output)

---

<img width="1904" height="1016" alt="Screenshot 2025-10-22 211023" src="https://github.com/user-attachments/assets/38c4d1f4-469b-441b-a9cd-55969d417e07" />
