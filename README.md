# 🎣 Phishing URL Detector

A Python-based heuristic engine that analyzes URLs for phishing 
indicators including brand spoofing, suspicious TLDs, IP-based URLs,
keyword analysis, and subdomain abuse.

---

## ⚡ Features

- **Brand Spoofing Detection** — Catches fake PayPal, Amazon, HDFC, SBI URLs
- **Suspicious TLD Check** — Flags .tk, .ml, .xyz, .click domains
- **IP-based URL Detection** — Flags raw IP addresses used instead of domains
- **Phishing Keyword Analysis** — Detects login, verify, secure, banking etc.
- **Subdomain Abuse Detection** — Catches deep subdomain tricks
- **Special Character Analysis** — Detects @ redirect tricks and encoding
- **Risk Scoring** — 0-8 score with verdict (Safe/Low/Medium/High)
- **Summary Table** — Clean verdict table for all analyzed URLs

---

## 🛠️ Setup & Installation

**Requirements:** Python 3.x (zero external libraries)

```bash
# Clone the repository
git clone https://github.com/s0xandrew/phishing-detector.git
cd phishing-detector

# Run the detector
python phishing_detector.py
```

---

## 📸 Sample Output
SUMMARY TABLE

URL                                          SCORE   VERDICT

https://www.google.com                       1       🟡 LOW RISK

https://github.com/s0xandrew                 0       ✅ LIKELY SAFE

http://paypal-secure-login.tk/verify         4       🟠 MEDIUM RISK

http://192.168.1.1/login                     4       🟠 MEDIUM RISK

http://hdfcbank-secure.ml/login/verify       4       🟠 MEDIUM RISK

https://sbi.co.in.secure-login.tk/banking    3       🟠 MEDIUM RISK
---

## 🧠 How It Works

### Brand Spoofing Detection
The most common phishing technique. Attacker registers a domain like
`paypal-secure-login.tk` and puts "paypal" in the URL to look legitimate.
The detector checks if a brand name appears in the URL but the real
domain doesn't match the official one.

### Suspicious TLD Analysis
Free TLDs (.tk, .ml, .ga, .cf) cost nothing and are heavily abused
for phishing campaigns because they're disposable and hard to trace.
Legitimate banks and companies never use these domains.

### IP-based URL Detection
Phishing sites sometimes use raw IPs (http://192.168.1.1/login)
to bypass domain blacklists. No legitimate financial service
sends you to an IP address.

### Subdomain Abuse
Attackers create URLs like `paypal.com.login.evil-site.tk` — 
the real domain is `evil-site.tk` but it looks like PayPal.
The detector counts subdomain depth to catch this.

---

## 🎯 Indian Banking Phishing Patterns Detected

This tool specifically targets phishing patterns affecting Indian users:

| Fake URL Pattern | Spoofing |
|-----------------|---------|
| sbi.co.in.secure-login.tk | SBI Bank |
| hdfcbank-secure.ml | HDFC Bank |
| icicibank-login.tk | ICICI Bank |

---

## 📁 Project Structure
phishing-detector/

│

├── phishing_detector.py    # Main detection engine

├── phishing_report.txt     # Auto-generated analysis report

└── README.md               # This file
---

## ⚖️ Ethical Use Disclaimer

This tool is for:
- Educational understanding of phishing techniques
- Analyzing URLs you personally received and suspect
- Security awareness training

Never use this tool to create or test actual phishing infrastructure.

---

## 🔗 B.Cyber Relevance

| Concept | Maps To |
|---------|---------|
| Phishing detection | Social engineering defense |
| Brand spoofing | Web-based attack patterns |
| Heuristic analysis | Threat detection methodology |
| URL parsing | Web security fundamentals |
| Indian banking focus | National cybersecurity relevance |

---

## 👨‍💻 Author

**Sourabh (s0xandrew)**
Self-taught cybersecurity enthusiast | JEE Main 2026
Building towards IIT Kanpur B.Cyber (Wadhwani School of AI)

---

## 📚 What I Learned

- How phishing URLs are constructed and why they fool people
- Brand spoofing and subdomain abuse techniques
- Heuristic scoring for threat detection
- Why free TLDs are dangerous
- Indian banking phishing patterns
- Python: regex, urllib.parse, string analysis, scoring systems
