# PhishGuard — Phishing URL Analyzer 🎣🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)]()
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red.svg)]()
[![Threat Intel](https://img.shields.io/badge/Tool-Threat_Intel-orange.svg)]()

**PhishGuard** is an advanced, automated Phishing URL Analyzer built to run entirely inside your browser. Designed for threat intelligence analysts, security operations, and everyday users to detect malicious links before clicking them. It instantly analyzes URLs using sophisticated heuristics, entropy calculation, and brand impersonation fingerprinting to provide a definitive risk score.

> **Google Search Keywords**: Phishing URL Analyzer, Malicious Link Checker, Anti-Phishing Tool, Cybersecurity Threat Intelligence, Identify Fake Websites, Detect Typosquatting, URL Entropy Calculator, Safe Browsing, PhishGuard.

---

## ✨ Features

- **🚀 100% Client-Side Processing**: No data is sent to a backend server. Maximum privacy and instantaneous real-time analysis.
- **🧠 Advanced Heuristic Engine**: Goes far beyond regex by scoring based on entropy (randomness), excessive subdomains, missing HTTPS, and IP-based links.
- **🛡️ Brand Impersonation Detection**: Specifically designed to catch typosquatting (e.g., *pypal.com* instead of *paypal.com*) targeting over 200+ high-value brands like Bank of America, Amazon, Apple, Google, and Microsoft.
- **📊 Granular Risk Scoring**: Provides a Risk Score (0-100) and assigns a threat level (Clean, Suspicious, Critical).
- **📝 Indicator Breakdown Table**: An intuitive tabular view showcasing exactly *why* a URL was flagged.
- **✨ Glassmorphism UI**: Beautiful, modern dark-mode aesthetic with interactive micro-animations optimized for an exceptional user experience.

---

## 🛠️ Installation & Setup

PhishGuard requires no database, no backend API, and no heavy dependencies. 

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YourUsername/phishing-analyzer.git
   ```
2. **Navigate to the Directory**:
   ```bash
   cd phishing-analyzer
   ```
3. **Run the Application**:
   Open `index.html` in your web browser.
   ```bash
   # On macOS
   open index.html

   # On Linux
   xdg-open index.html

   # On Windows
   start index.html
   ```

---

## 💻 How to Use

1. **Launch the Analyzer**: Open `index.html`.
2. **Input URL**: Paste the suspicious link into the text input area.
3. **Analyze**: Click the **Analyze URL** button.
4. **Review Results**:
   - The **Risk Ring** visually represents the threat level.
   - The **Verdict Badge** explicitly states if it's safe or dangerous.
   - The **Threat Level Bar** fills based on urgency.
   - Consult the **Findings Cards** and the **Indicator Breakdown** section to understand the specific triggers (e.g., High Entropy, Free Hosting domain, Suspicious Keywords).

---

## 🔬 How Does it Detect Phishing?

PhishGuard scores URLs across multiple threat vectors:
- **IP-Based Hosting**: Flags `http://192.168.1.1/login` formats.
- **Typosquatting & Brand Spoofing**: Levenshtein-style analysis identifying visually similar strings to top brands.
- **High Entropy Paths**: Detects randomized directories commonly seen in phishing kits (e.g., `/secure/login/a8b9cdef12345/verify`).
- **Phishing Keywords**: Flags tokens like `secure`, `verify`, `account`, `update`, `signin` found outside the base domain.
- **Suspicious TLDs**: Penalizes domains using ultra-cheap or heavily abused Top-Level Domains (TLDs) like `.top`, `.tk`, `.ml`, `.xyz`.
- **Length and Structure Anomalies**: Flags extraordinarily long URLs or those with an excessive number of subdomains.

---

## 🤝 Contributing

We welcome community contributions.

1. **Fork** the project.
2. Create your **Feature Branch** (`git checkout -b feature/NewFeature`).
3. Commit your changes (`git commit -m 'Add NewFeature'`).
4. **Push** to the branch (`git push origin feature/NewFeature`).
5. Open a **Pull Request**.

---

## ⚠️ Disclaimer

PhishGuard analyzes URLs locally within your browser for immediate triage. While highly effective, it should not be the sole determinant for critical, high-risk security decisions. Always verify with your organizational SOC team or utilize sandboxed execution for highly suspicious artifacts.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

> *Created with ❤️ by Abenezer. Stay safe online.*
