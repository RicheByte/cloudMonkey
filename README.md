#  cloudMonkey

#  Cloud Security Scanner - Enterprise Edition v8.0

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

**Next-generation cloud security misconfiguration scanner with enterprise features.**
![Demo Video](/assets/video.gif)
---

##  What's New in v8.0

### Major Features Added:
-  **Persistent Storage** - SQLite database for scan history & trend analysis
-  **Rules Engine** - YAML-based signature detection (community-driven)
-  **Multi-Cloud Support** - 6 cloud providers: AWS, GCP, Azure, DigitalOcean, Oracle, Alibaba
-  **Compliance Frameworks** - ISO27001, SOC2, NIST 800-53, PCI-DSS mapping
-  **Enhanced Reporting** - CVSS v3.1, OWASP Top 10, MITRE ATT&CK integration
-  **Scan Comparison** - Track security posture changes over time
-  **Docker Support** - Production-ready containerization
-  **Parallel Processing** - 5-10x faster with optimized async operations

---

##  Quick Start

### Installation
```bash
git clone https://github.com/RicheByte/cloudMonkey.git
cd cloudMonkey
pip install -r requirements.txt
```

### Run Setup (Recommended)
```bash
python setup.py
```

### Basic Scan
```bash
python cloud-pro.py example.com
```

### HTML Report
```bash
python cloud-pro.py example.com --format html --output report.html
```

---

##  Core Capabilities

### Security Checks
-  SSL/TLS certificate validation & expiration
-  HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- DNS configuration (SPF, DMARC, CAA records)
- Sensitive file exposure (.env, .git, config files)
- CORS policy misconfiguration
- Server information disclosure
- **Multi-cloud storage buckets** (AWS S3, GCP, Azure, DO, Oracle, Alibaba)
-  Subdomain takeover risks
-  Open port scanning (databases, admin panels)

### Intelligence Features
- 🌐 Passive intelligence (Shodan, VirusTotal, SecurityTrails)
- 🔬 Intelligent false positive filtering
- 📊 Normalized risk scoring (0-100 scale)
- 🎯 Multi-mode scanning (Safe, Normal, Aggressive, Stealth)

---

##  Usage Examples

### Comprehensive Enterprise Scan
```bash
python cloud-pro.py example.com \
  --mode aggressive \
  --format html \
  --output report.html \
  --compliance iso27001 \
  --verbose
```

### Compare Scans Over Time
```bash
# First scan
python cloud-pro.py example.com

# ... make changes ...

# Second scan
python cloud-pro.py example.com

# Compare
python cloud-pro.py --compare example.com
```

### View Scan History
```bash
python cloud-pro.py --history example.com
```

### Generate Compliance Report
```bash
python cloud-pro.py example.com --compliance iso27001
# Options: iso27001, soc2, nist_800_53, pci_dss
```

### Docker Deployment
```bash
# Build
docker build -t cloudmonkey:v7 .

# Run scan
docker run -v $(pwd)/data:/data cloudmonkey:v7 example.com

# With HTML report
docker run -v $(pwd)/data:/data -v $(pwd)/reports:/reports \
  cloudmonkey:v7 example.com --format html --output /reports/scan.html
```

---

##  Project Structure

```
cloudMonkey/
├── cloud-pro.py              # Main scanner (enhanced v7.0)
├── db_manager.py             #  NEW: Database persistence
├── rules_engine.py           #  NEW: YAML rules engine
├── requirements.txt          # Dependencies
├── setup.py                  #  NEW: Interactive setup
├── Dockerfile                #  NEW: Container build
├── docker-compose.yml        #  NEW: Compose configuration
│
├── rules/                    #  NEW: Detection signatures
│   ├── aws_s3_public.yaml
│   ├── gcp_storage_public.yaml
│   ├── azure_blob_public.yaml
│   ├── digitalocean_spaces.yaml
│   ├── ssl_expired.yaml
│   ├── missing_security_headers.yaml
│   ├── exposed_git.yaml
│   └── exposed_env.yaml
│
├── data/                     # Scan database (auto-created)
│   └── scan_history.db
│
├── reports/                  # Output reports (auto-created)
│
└── doc/                      # Documentation
    ├── ENHANCEMENTS.md       #  NEW: Feature documentation
    ├── QUICKSTART.md         #  NEW: Quick start guide
    ├── IMPLEMENTATION_SUMMARY.md  #  NEW: Technical details
    └── PERFORMANCE_IMPROVEMENTS.md
```

---

##  Advanced Features

### Custom Rules
Create `rules/my-custom-rule.yaml`:
```yaml
id: MY_CUSTOM_CHECK
name: Custom Security Check
description: Detect custom vulnerability
severity: high
confidence: high
category: custom
patterns:
  - type: response_body
    regex: "sensitive_pattern"
remediation: |
  Step-by-step fix instructions
cvss:
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
  score: 7.5
owasp_top10:
  - "A01:2021 - Broken Access Control"
mitre_attack:
  - "T1190 - Exploit Public-Facing Application"
compliance:
  iso27001: ["A.9.1.2"]
  soc2: ["CC6.1"]
```

### API Configuration
```bash
# Generate template
python cloud-pro.py --generate-config

# Edit api_config_template.json

![Demo Video](/assets/apis.png)

# Add your API keys (optional)

# Use config
python cloud-pro.py example.com --config api_config_template.json
```

### CLI Options
```
--mode {safe,normal,aggressive,stealth}  # Scan intensity
--format {text,json,html,markdown}       # Report format
--compliance {iso27001,soc2,nist,pci}    # Framework report
--history <domain>                       # View scan history
--compare <domain>                       # Compare scans
--no-db                                  # Disable database
--no-verify                              # Skip verification (faster)
--timeout <seconds>                      # Request timeout
--workers <count>                        # Concurrent workers
```

---

##  Scan Modes

| Mode | Checks | Use Case |
|------|--------|----------|
| **Safe** | Non-intrusive only | Production systems |
| **Normal** | Standard checks | General security audits |
| **Aggressive** | Deep scanning + probing | Penetration testing |
| **Stealth** | Evasion techniques | Red team operations |

---

##  Compliance Frameworks

### Supported Standards:
- **ISO 27001** - Information security management
- **SOC 2** - Service organization controls
- **NIST 800-53** - Federal security controls
- **PCI DSS** - Payment card industry

**Example Output:**
```
📋 ISO27001 Compliance Report
================================
Compliance Score: 73.5/100
Controls Affected: 12
Total Findings: 8

Affected Controls:
  - A.9.1.2 (Access Control): 3 findings
  - A.13.1.3 (Network Security): 2 findings
  - A.10.1.1 (Cryptographic Controls): 3 findings
```

---

##  Docker Usage

### Basic
```bash
docker run cloudmonkey:v7 example.com
```

### With Persistence
```bash
docker run -v ./data:/data cloudmonkey:v7 example.com
```

### Docker Compose
```bash
docker-compose up scanner
```

---

##  CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    python cloud-pro.py ${{ secrets.DOMAIN }} --format json -o scan.json
    SCORE=$(jq '.risk_score' scan.json)
    if [ $SCORE -gt 70 ]; then exit 1; fi
```

### Jenkins Pipeline
```groovy
stage('Security Scan') {
    steps {
        sh 'python cloud-pro.py ${DOMAIN} --format json -o scan.json'
        script {
            def score = readJSON(file: 'scan.json').risk_score
            if (score > 70) error("Risk too high: ${score}")
        }
    }
}
```

---

##  Performance

### Optimizations:
-  Connection pooling with TCP reuse
-  DNS caching (5-min TTL)
-  SSL certificate caching
-  Parallel cloud storage checks
-  Concurrent API intelligence gathering
-  Session reuse across all HTTP checks
-  Database connection pooling

**Result:** 5-10x faster than previous versions!



##  Contributing

Contributions welcome! Especially:
- New YAML detection rules
- Cloud provider patterns
- Compliance framework mappings
- Performance optimizations

**Submit PRs:** https://github.com/RicheByte/cloudMonkey/pulls

---

##  License

MIT License - See [LICENSE](LICENSE) for details

---

##  Author

**RicheByte**
- GitHub: [@RicheByte](https://github.com/RicheByte)
- Version: 7.0-ENTERPRISE
- Released: November 2025

---

##  Disclaimer

**For authorized security testing only.** Always obtain proper authorization before scanning systems you don't own.

---

##  Star This Project

If you find this tool useful, please give it a star  on GitHub!

---

**Status: Production Ready** 
