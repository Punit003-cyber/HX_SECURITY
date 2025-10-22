# HX Threat Intell Platform – Security & Privacy Policy

## 🛡️ Data Protection Principles

1. **Local-First Analysis**  
   - All data collection and scanning happen on the user’s system by default.  
   - No automatic cloud upload or external data transmission.

2. **User-Controlled APIs**  
   - External reputation checks (VirusTotal, Shodan, etc.) only run if the user provides their own API keys.  
   - These keys are stored securely in local `.env` files, not embedded in code.

3. **Anonymized Logging**  
   - The platform avoids collecting personal identifiers.  
   - Only necessary metadata (timestamps, filenames, URLs) is analyzed.

4. **Transparency**  
   - All outputs are stored as readable JSON files so users can inspect every event.

---

## 🔒 Recommendations for Users
- Store your `.env` file securely and **never** share it publicly.  
- Review your local output folders before sharing logs externally.  
- Rotate API keys regularly.

---

## ⚠️ Responsible Use
HX Threat Intell Platform is intended for **ethical cybersecurity research and defense** only.  
Any misuse (such as unauthorized data extraction or privacy violation) is strictly against HX policies.

---

## 🧾 Contact
If you discover a vulnerability or have a privacy concern, please contact:

**HX Security Labs**  
📧 Email: [security@hxsecurity.com](mailto:security@hxsecurity.com)
