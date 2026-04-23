# CyberSentinel - Threat Intelligence Dashboard

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Complete-success.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![APIs](https://img.shields.io/badge/APIs-4%20Integrated-brightgreen.svg)

##  Project Overview

**CyberSentinel** is an open-source threat intelligence dashboard that aggregates, analyzes, and visualizes cybersecurity threats in real-time. Built for security professionals, SOC analysts, and organizations, it provides comprehensive monitoring capabilities by integrating data from four major cybersecurity data sources into a single unified interface.

###  Academic Project Information
- **Course:** ITMS 548 - Cybersecurity Technologies
- **Institution:** Illinois Institute of Technology
- **Instructor:** Dr. Maurice Dawson
- **Semester:** Spring 2026
- **Timeline:** April 10-28, 2026

###  Team Members
| Role | Name |
|------|------|
| Project Lead &  Developer | Dennis Oseitutu |
| Security Researcher & Developer | Akinyemi Aremu |
| Network Security Specialist & Developer| William Smith |

---

## Key Features

### Real-Time Threat Intelligence
- Live CVE vulnerability monitoring
- IP reputation checking against abuse databases
- URL and file malware scanning
- Threat intelligence pulse aggregation

### Data Analysis & Visualization
- **Vulnerability Severity Distribution** (Pie Chart)
- **IP Risk Distribution** (Bar Chart)
- **Geographic Threat Distribution** (Country Analysis)
- **Vulnerability Timeline** (Time Series)
- **Summary Statistics Dashboard**
- **Exportable Reports** (Text format)

### Data Management
- SQLite database for persistent storage
- Automatic data caching
- Query history tracking
- Activity logging

###  User Experience
- Clean, professional Tkinter GUI
- 6 functional tabs for different operations
- Menu system with File, Tools, and Help options
- Real-time status updates
- Activity log display

---

##  Integrated Data Sources

CyberSentinel integrates with **four major cybersecurity APIs**:

| # | API | Purpose | Free Tier |
|---|-----|---------|-----------|
| 1 | **NVD (National Vulnerability Database)** | CVE vulnerability data |  Yes |
| 2 | **AbuseIPDB** | IP address reputation |  1,000 req/day |
| 3 | **VirusTotal** | URL/file malware scanning |  4 req/min |
| 4 | **AlienVault OTX** | Threat intelligence pulses |  Yes |

---

##  Technology Stack

### Core Technologies
| Component | Technology | Version |
|-----------|-----------|---------|
| **Language** | Python | 3.11+ |
| **GUI Framework** | Tkinter | Built-in |
| **Database** | SQLite3 | Built-in |
| **HTTP Client** | requests | 2.31.0 |
| **Data Processing** | pandas | 2.2.0 |
| **Numerical Computing** | numpy | 1.26.3 |
| **Visualization** | matplotlib | 3.8.2 |

### Development Tools
- **Version Control:** Git & GitHub
- **IDE:** Visual Studio Code
- **Testing:** pytest 7.4.4
- **Code Style:** PEP 8

---

##  Installation

### Prerequisites

Before installing CyberSentinel, ensure you have:
-  **Python 3.11+** ([Download](https://www.python.org/downloads/))
-  **pip** package manager (included with Python)
-  **Git** ([Download](https://git-scm.com/downloads))
-  **Internet connection** for API access

### Step-by-Step Setup

#### 1. Clone the Repository
```bash
git clone https://github.com/Dennistutu/cybersentinel-itms548.git
cd cybersentinel-itms548
```

#### 2. Create Virtual Environment
```bash
# Create venv
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on Linux/macOS
source venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

This installs: requests, pandas, numpy, matplotlib, pytest, python-dateutil

#### 4. Configure API Keys
```bash
# Copy example config
cp config/config.example.json config/config.json

# Edit config/config.json with your API keys (see API Setup below)
```

#### 5. Run the Application
```bash
python src/main.py
```

The CyberSentinel GUI will launch! 

---

##  API Key Setup

All APIs offer **FREE tiers** - registration takes ~10 minutes total.

### 1. NVD (National Vulnerability Database)
- **Website:** https://nvd.nist.gov/developers/request-an-api-key
- **Purpose:** CVE vulnerability data
- **Free Tier:** Works without key (slower), or register for API key
- **Rate Limit:** 5 req/30s (public), 50 req/30s (with key)

### 2. AbuseIPDB
- **Website:** https://www.abuseipdb.com/register
- **Purpose:** IP reputation checking
- **Free Tier:** 1,000 requests/day
- **Registration:** Email verification required

### 3. VirusTotal
- **Website:** https://www.virustotal.com/gui/join-us
- **Purpose:** URL/file malware scanning
- **Free Tier:** 4 requests/minute, 500 requests/day
- **Registration:** Email verification required

### 4. AlienVault OTX
- **Website:** https://otx.alienvault.com/
- **Purpose:** Threat intelligence feeds
- **Free Tier:** Full access (reasonable use)
- **Registration:** Email verification required

### Configuration File

Edit `config/config.json`:

```json
{
  "api_keys": {
    "nvd": "your-nvd-api-key-here",
    "abuseipdb": "your-abuseipdb-key-here",
    "virustotal": "your-virustotal-key-here",
    "alienvault_otx": "your-otx-key-here"
  },
  "settings": {
    "cache_enabled": true,
    "cache_duration_hours": 24,
    "max_api_retries": 3,
    "request_timeout": 30,
    "log_level": "INFO"
  },
  "database": {
    "path": "data/cybersentinel.db"
  }
}
```

** IMPORTANT:** Never commit `config.json` to Git (it's in `.gitignore`)

---

##  Project Structure

```
cybersentinel-itms548/
│
├── src/                          # Source code
│   ├── main.py                   # Application entry point
│   │
│   ├── gui/                      # GUI components
│   │   └── main_window.py        # Main application window (6 tabs)
│   │
│   ├── api/                      # API integrations
│   │   ├── nvd_api.py            # NVD CVE lookup
│   │   ├── abuseipdb_api.py      # IP reputation
│   │   ├── virustotal_api.py     # URL/file scanning
│   │   └── otx_api.py            # Threat intelligence
│   │
│   ├── analysis/                 # Data analysis
│   │   └── data_analyzer.py      # Charts & statistics
│   │
│   ├── database/                 # Database operations
│   │   └── db_manager.py         # SQLite manager
│   │
│   └── utils/                    # Utilities
│       ├── config.py             # Configuration manager
│       └── logger.py             # Logging system
│
├── config/                       # Configuration
│   ├── config.example.json       # Template
│   └── config.json               # Your keys (not in Git)
│
├── data/                         # Local data (auto-created)
│   ├── cybersentinel.db          # SQLite database
│   └── cybersentinel_*.log       # Log files
│
├── tests/                        # Unit tests
├── docs/                         # Additional documentation
│
├── requirements.txt              # Python dependencies
├── README.md                     # This file
├── API_SETUP_GUIDE.md            # Quick API setup
├── LICENSE                       # MIT License
└── .gitignore                    # Git ignore rules
```

---

##  Usage Guide

### Application Tabs Overview

####  1. Dashboard Tab
**Purpose:** System overview and activity monitoring

**Features:**
- Total Vulnerabilities counter
- IP Reputation Checks counter
- File/URL Scans counter
- Threat Intelligence Pulses counter
- Real-time activity log
- Manual refresh button

####  2. Vulnerabilities Tab
**Purpose:** Search CVE database

**How to Use:**
1. Enter keyword (e.g., "Apache", "Microsoft") or CVE ID
2. Click "Search" button
3. View results with CVSS scores and descriptions
4. Data automatically saved to database

**Example Searches:**
- `Microsoft` - Microsoft products CVEs
- `Apache` - Apache-related vulnerabilities
- `CVE-2024-1234` - Specific CVE lookup

####  3. IP Reputation Tab
**Purpose:** Check IP address reputation

**How to Use:**
1. Enter IP address (e.g., `8.8.8.8`)
2. Click "Check Reputation"
3. View abuse confidence score and reports

**Risk Levels:**
-  **LOW RISK** (0-25%): Likely clean
-  **MEDIUM RISK** (26-74%): Suspicious activity
-  **HIGH RISK** (75-100%): Likely malicious

**Test IPs:**
- `8.8.8.8` - Google DNS (clean)
- `185.220.101.1` - Known malicious (Tor exit)

####  4. Scan Tab
**Purpose:** Scan URLs and files for malware

**How to Use:**
1. Enter URL (e.g., `https://example.com`) or file hash (SHA-256)
2. Click "Scan"
3. View detection results from 70+ antivirus engines

**Example:**
- URL: `https://www.google.com` → Should be clean
- Malicious URL → Shows detection ratio

####  5. Threat Intel Tab
**Purpose:** Search threat intelligence pulses

**How to Use:**
1. Enter threat term (e.g., "ransomware", "phishing")
2. Click "Search Pulses"
3. Browse threat intelligence with indicators

**Example Searches:**
- `ransomware` - Ransomware campaigns
- `phishing` - Phishing attacks
- `APT` - Advanced Persistent Threats

####  6. Analytics Tab
**Purpose:** Data visualization and reporting

**Features:**
- **Summary Statistics** - Total counts
- **Vulnerability Severity Pie Chart** - CRITICAL/HIGH/MEDIUM/LOW distribution
- **IP Risk Distribution Bar Chart** - Risk categorization
- **Geographic Distribution** - Top countries by IP checks
- **Vulnerability Timeline** - CVEs over time
- **Export Report Button** - Save text report

### Menu Options

#### File Menu
- **Settings** - Application settings
- **Exit** - Close application

#### Tools Menu
- **Refresh Dashboard** - Update statistics
- **Clear Cache** - Clear cached data
- **Export Data** - Export database

#### Help Menu
- **About** - Application information
- **API Setup Guide** - API configuration help

---

##  Database Schema

CyberSentinel uses SQLite with 5 tables:

### `vulnerabilities`
Stores CVE data from NVD
- cve_id, description, severity, cvss_score, published_date, last_modified

### `ip_reputation`
Stores IP check results from AbuseIPDB
- ip_address, abuse_confidence_score, country_code, usage_type, total_reports

### `scan_results`
Stores URL/file scan results from VirusTotal
- scan_type, target, positives, total_scans, scan_date, malicious

### `threat_pulses`
Stores threat intelligence from AlienVault OTX
- pulse_id, name, description, author, tags, indicator_count

### `query_history`
Tracks all user queries
- query_type, query_value, result_count, success, timestamp

---

##  Testing

### Running the Test Suite
```bash
pytest tests/
```

### Test Coverage
```bash
pytest --cov=src tests/
```

### Manual Testing
See `Test_Document.docx` for comprehensive test cases and results.

### Test Results Summary
-  **10/10** test cases passed
-  **100%** pass rate
-  **12/12** requirements met

---

##  Data Analysis Features

### Statistical Analysis
- Vulnerability count by severity
- IP risk categorization
- Geographic distribution
- Temporal trend analysis

### Visualizations
- Pie charts for categorical data
- Bar charts for distributions
- Line charts for time series
- Horizontal bar charts for rankings

### Export Options
- Text reports (.txt format)
- CSV export (via data analyzer)
- Future: PDF reports

---

##  Security Considerations

### API Key Protection
- Config file excluded from version control (`.gitignore`)
- API keys never logged or displayed
- Environment variable support recommended for production

### Data Privacy
- All data stored locally (SQLite)
- No telemetry or analytics
- Your queries stay on your machine

### Network Security
- HTTPS for all API communications
- Request timeouts to prevent hangs
- Rate limiting compliance

---

##  Project Statistics

- **Total Lines of Code:** ~2,500+
- **Number of Files:** 15+
- **API Integrations:** 4
- **GUI Tabs:** 6
- **Chart Types:** 4
- **Database Tables:** 5
- **Development Time:** 12 days

---

##  Troubleshooting

### Common Issues

#### "ModuleNotFoundError: No module named 'X'"
**Solution:** Install missing dependencies
```bash
pip install -r requirements.txt
```

#### "API key not configured"
**Solution:** Add your API key to `config/config.json`

#### "Rate limit exceeded"
**Solution:**
- VirusTotal: Wait 1 minute (4 req/min limit)
- AbuseIPDB: Check daily quota (1,000/day)

#### Charts not displaying
**Solution:** Install matplotlib and pandas
```bash
pip install matplotlib pandas
```

#### GUI not launching
**Solution:** Ensure Tkinter is installed
```bash
# On Linux
sudo apt-get install python3-tk
```

---

##  Future Enhancements

Potential features for future development:

- [ ] **Export to PDF** - Generate PDF reports
- [ ] **Scheduled Scans** - Automated periodic scans
- [ ] **Email Alerts** - Notify on high-risk findings
- [ ] **Dark Mode** - UI theme toggle
- [ ] **Multi-language Support** - Internationalization
- [ ] **More APIs** - Shodan, Censys, URLhaus integration
- [ ] **Bulk Operations** - Process IP/URL lists
- [ ] **API Key Vault** - Encrypted key storage
- [ ] **Custom Dashboards** - User-configurable widgets
- [ ] **REST API** - Expose functionality as web service

---

##  Contributing

This is an academic project for ITMS 548. Contributions welcome after project submission!

### Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Code Style
- Follow PEP 8 guidelines
- Add docstrings to all functions
- Write unit tests for new features
- Update documentation

---

##  License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

```
MIT License - Copyright (c) 2026 Dennis Oseitutu, Akinyemi Aremu, William Smith
```

---

##  Disclaimer

**CyberSentinel is an educational tool developed for academic purposes.**

-  Uses legitimate, public threat intelligence sources
-  Helps security professionals gather intelligence
-  Should NOT be sole source for critical security decisions
-  NOT intended for malicious use

Always validate findings with multiple sources and consult security professionals for critical decisions.

---

##  Acknowledgments

### Academic
- **Dr. Maurice Dawson** - ITMS 548 Course Instructor
- **Illinois Institute of Technology** - Academic institution
- **ITMS 548 Cybersecurity Technologies** - Course framework

### Data Sources
- **National Institute of Standards and Technology (NIST)** - NVD API
- **AbuseIPDB Community** - Community-driven IP reputation
- **Google (VirusTotal)** - Multi-engine malware scanning
- **AT&T Cybersecurity (AlienVault)** - OTX platform

### Open Source Tools
- **Python Software Foundation** - Python language
- **Tcl/Tk Team** - Tkinter GUI framework
- **Matplotlib Development Team** - Visualization library
- **pandas Development Team** - Data analysis library
- **SQLite Team** - Embedded database

---

##  Contact & Support

### Project Repository
**GitHub:** https://github.com/Dennistutu/cybersentinel-itms548

### Issues & Bug Reports
Please open an issue on GitHub:
https://github.com/Dennistutu/cybersentinel-itms548/issues

### Team Contact
For academic inquiries, contact team members through IIT student directory.

---

##  Additional Resources

### Project Documentation
- [API Setup Guide](API_SETUP_GUIDE.md) - Quick API configuration
- Project Plan (Canvas submission)
- Risk Management Plan (Canvas submission)
- Project Management Plan (Canvas submission)
- Earned Value Sheet (Canvas submission)
- Test Document (Canvas submission)

### External References
- [NVD Documentation](https://nvd.nist.gov/developers)
- [AbuseIPDB API Docs](https://docs.abuseipdb.com/)
- [VirusTotal API v3](https://developers.virustotal.com/reference)
- [AlienVault OTX API](https://otx.alienvault.com/api)

---

##  Project Achievements

-  **100% Requirements Met** - All 12 rubric requirements satisfied
-  **All Tests Passed** - 10/10 test cases successful
-  **4 APIs Integrated** - Real threat intelligence
-  **6 Visualizations** - Comprehensive data analysis
-  **Professional Documentation** - Enterprise-grade docs
-  **Clean Code** - PEP 8 compliant, well-documented
-  **Version Controlled** - Complete Git history
-  **Open Source** - MIT Licensed

---

**Made with love by Team CyberSentinel**

**ITMS 548 - Cybersecurity Technologies | Illinois Institute of Technology | Spring 2026**
