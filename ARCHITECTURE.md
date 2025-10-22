# HX Threat Intell Platform – System Architecture

## 🔄 Overview
HX Threat Intell Platform is built around four coordinated modules that work together to create a full endpoint and browser threat intelligence pipeline.


---

## 🧱 Modules and Data Flow

| Step | Module | Description |
|------|---------|-------------|
| **1️⃣ Data Collection** | **Log Collector** | Continuously captures endpoint activity, including system logs, processes, network events, and security telemetry. |
| **2️⃣ Browser Extraction** | **Browser Extractor** | Periodically gathers browser artifacts such as history, cookies, bookmarks, and downloads for contextual threat intelligence. |
| **3️⃣ Threat Analysis** | **Scanner** | Analyzes the collected JSON logs and browser data using detection rules, IOC databases, and external reputation APIs like VirusTotal and Shodan. |
| **4️⃣ Visualization** | **Dashboard** | Presents analysis results through charts, KPIs, and JSON viewers to help users identify threats and trends. |

---

## ⚙️ Data Processing Flow

1. **Log & Browser Collection**
   - Data gathered from endpoints and browsers.
   - Converted into structured JSON format.
2. **Central Scanning**
   - Each JSON file is parsed and scanned.
   - Threat rules and external lookups (hash, IP, domain reputation) are applied.
3. **Classification**
   - Results are labeled (Safe / Suspicious / Malicious).
   - Stored in structured “results” folders or databases.
4. **Visualization**
   - The dashboard summarizes collected data.
   - Displays hourly trends, browser statistics, and threat severity charts.

---

## 🧠 Design Philosophy
- **Modular:** Each component runs independently but integrates seamlessly.  
- **Scalable:** Can be extended to handle more data sources (e.g., cloud logs).  
- **Local-first:** Prioritizes offline and on-device analysis for privacy.  
- **Transparent:** All outputs saved as structured JSON for easy validation.

---

## 🛠️ Future Architecture Additions
- Cloud-based API integration for distributed endpoints.  
- Machine learning layer for behavior-based anomaly detection.  
- Integration with SIEM or SOC dashboards (Splunk, ELK, etc.).
