# CyberSentinel - Threat Intelligence Dashboard

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange.svg)

## 📋 Project Overview

CyberSentinel is an open-source threat intelligence dashboard that aggregates, analyzes, and visualizes cybersecurity threats in real-time. Built for security professionals and organizations, it provides comprehensive monitoring capabilities by integrating data from multiple authoritative cybersecurity sources.

**Course:** ITMS 548 - Cybersecurity Technologies  
**Institution:** Illinois Institute of Technology  
**Team:** Dennis Oseitutu, Akinyemi Aremu, William Smith  
**Timeline:** April 16-28, 2026

---

## ✨ Features

- **Real-time Threat Monitoring** - Live updates from multiple threat intelligence feeds
- **Multi-Source Integration** - Aggregates data from 4+ cybersecurity APIs
- **Vulnerability Tracking** - CVE database integration with severity scoring
- **IP Reputation Analysis** - Check suspicious IP addresses against threat databases
- **File/URL Scanning** - Malware and phishing detection capabilities
- **Data Visualization** - Interactive charts and graphs for threat trends
- **Risk Assessment** - Automated threat scoring and prioritization
- **Intuitive GUI** - User-friendly desktop interface built with Tkinter

---

## 🔌 Data Sources

1. **National Vulnerability Database (NVD)** - CVE and vulnerability data
2. **AbuseIPDB** - IP address reputation and abuse reporting
3. **VirusTotal** - File and URL malware scanning
4. **AlienVault OTX** - Open Threat Exchange intelligence feeds

---

## 🛠️ Technology Stack

- **Language:** Python 3.11+
- **GUI Framework:** Tkinter (built-in)
- **Data Processing:** pandas, NumPy
- **Visualization:** Matplotlib
- **Database:** SQLite3 (embedded)
- **HTTP Requests:** requests library
- **Testing:** pytest

---

## 📦 Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager
- Internet connection for API access

### Setup Instructions

1. **Clone the repository:**
```bash
git clone https://github.com/[your-username]/cybersentinel.git
cd cybersentinel
```

2. **Create virtual environment:**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure API keys:**
```bash
cp config/config.example.json config/config.json
# Edit config/config.json and add your API keys
```

5. **Run the application:**
```bash
python src/main.py
```

---

## 🔑 API Key Setup

CyberSentinel requires API keys from the following services (all free tier available):

### 1. National Vulnerability Database (NVD)
- **URL:** https://nvd.nist.gov/developers/request-an-api-key
- **Tier:** Free (no key required, but rate limited)
- **Limit:** 5 requests per 30 seconds (without key), 50/30s (with key)

### 2. AbuseIPDB
- **URL:** https://www.abuseipdb.com/api
- **Tier:** Free (requires registration)
- **Limit:** 1,000 requests per day

### 3. VirusTotal
- **URL:** https://www.virustotal.com/gui/join-us
- **Tier:** Free (requires registration)
- **Limit:** 4 requests per minute

### 4. AlienVault OTX
- **URL:** https://otx.alienvault.com/api
- **Tier:** Free (requires registration)
- **Limit:** No strict limit (reasonable use)

Add your keys to `config/config.json`:
```json
{
  "api_keys": {
    "nvd": "your-nvd-api-key-here",
    "abuseipdb": "your-abuseipdb-key-here",
    "virustotal": "your-virustotal-key-here",
    "alienvault_otx": "your-otx-key-here"
  }
}
```

---

## 📁 Project Structure

```
cybersentinel/
├── src/                    # Source code
│   ├── main.py            # Application entry point
│   ├── gui/               # GUI components
│   ├── api/               # API integrations
│   ├── analysis/          # Data analysis modules
│   ├── database/          # Database operations
│   └── utils/             # Utility functions
├── tests/                 # Unit tests
├── docs/                  # Documentation
├── data/                  # Local data storage
├── config/                # Configuration files
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── LICENSE               # MIT License
```

---

## 🚀 Usage

### Basic Workflow

1. **Launch Application**
   ```bash
   python src/main.py
   ```

2. **Dashboard Overview**
   - View real-time threat statistics
   - Monitor recent CVE vulnerabilities
   - Check trending threats

3. **IP Reputation Check**
   - Enter IP address
   - View reputation score and abuse reports
   - See geographic information

4. **File/URL Scan**
   - Upload file or enter URL
   - View scan results from multiple engines
   - Get threat classification

5. **Vulnerability Search**
   - Search CVE database
   - Filter by severity, date, vendor
   - Export results

6. **Generate Reports**
   - Export data visualizations
   - Create PDF reports
   - Save analysis results

---

## 🧪 Testing

Run the test suite:
```bash
pytest tests/
```

Run with coverage:
```bash
pytest --cov=src tests/
```

---

## 📊 Data Analysis Features

- **Vulnerability Trends** - Historical CVE data analysis
- **Threat Scoring** - Automated risk assessment algorithms
- **Geographic Distribution** - Map-based threat visualization
- **Severity Analysis** - CVSS score distribution
- **Time Series Analysis** - Trend detection over time

---

## 🤝 Contributing

This is an academic project developed for ITMS 548. Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 Documentation

Full documentation available in the `docs/` directory:
- [Installation Guide](docs/installation.md)
- [User Manual](docs/user_manual.md)
- [API Reference](docs/api_reference.md)
- [Developer Guide](docs/developer_guide.md)

---

## ⚠️ Disclaimer

CyberSentinel is an educational tool developed for academic purposes. While it uses real threat intelligence sources, it should not be used as the sole source for critical security decisions. Always validate findings with multiple sources and consult security professionals.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Team

- **Dennis Oseitutu** - Project Lead & Lead Developer
- **Akinyemi Aremu** - Security Researcher
- **William Smith** - Network Security Specialist

---

## 🙏 Acknowledgments

- Illinois Institute of Technology - ITMS 548 Course
- National Vulnerability Database (NIST)
- AbuseIPDB Community
- VirusTotal by Google
- AlienVault Open Threat Exchange
- Open-source Python community

---

## 📧 Contact

For questions or support, please open an issue in the GitHub repository.

---

**Made with ❤️ for Cybersecurity**
