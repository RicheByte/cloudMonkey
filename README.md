#  cloudMonkey

**Advanced Cloud Security Scanner & Misconfiguration Detection Toolkit**

> *"The cloud is vast, but cloudMonkey makes it visible."*

cloudMonkey is a high-performance Python toolkit for cloud reconnaissance and security assessment. It provides **three distinct scanning engines** optimized for different use cases—from rapid development checks to comprehensive production audits.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Performance](https://img.shields.io/badge/Performance-3--5x_Optimized-brightgreen.svg)](PERFORMANCE_IMPROVEMENTS.md)

---

##  Quick Start

```bash
# Clone and setup
git clone https://github.com/RicheByte/cloudMonkey.git
cd cloudMonkey
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run a quick scan
python cloud-mini.py example.com

# Full security assessment
python cloud-pro.py example.com --mode normal --format html -o report.html
```

---

##  Three Scanning Engines

cloudMonkey offers **three purpose-built scanners** to match your needs:

### 🔹 **cloud-mini.py** — Lightning Fast Reconnaissance
**Use Case:** Development, CI/CD pipelines, quick sanity checks  
**Speed:** ⚡⚡⚡ (3-5 seconds)  
**Depth:** Basic coverage

```bash
python cloud-mini.py example.com
```

**Features:**
- ✅ Minimal dependencies
- ✅ HTTP security headers
- ✅ SSL/TLS validation
- ✅ DNS records (SPF, DMARC)
- ✅ Common sensitive files
- ✅ Perfect for automated testing

**Ideal For:**
- Developer workflows
- Integration tests
- Pre-deployment checks
- CTF reconnaissance

---

###  **cloud.py** — Balanced Security Scanning
**Use Case:** CTFs, security labs, training, demos  
**Speed:** ⚡⚡ (10-20 seconds)  
**Depth:** Moderate coverage

```bash
python cloud.py example.com
```

**Features:**
- ✅ Everything in mini, plus:
- ✅ CORS policy analysis
- ✅ Server header inspection
- ✅ Basic S3 bucket enumeration
- ✅ Common port scanning
- ✅ Subdomain takeover checks

**Ideal For:**
- Bug bounty hunting
- Security workshops
- Educational purposes
- Penetration testing labs

---

###  **cloud-pro.py** — Ultimate Professional Scanner
**Use Case:** Production audits, comprehensive assessments  
**Speed:** ⚡ (8-15 seconds with optimizations)  
**Depth:** Maximum coverage

```bash
python cloud-pro.py example.com --mode aggressive  --format html -o report.html
```

**Features:**
- ✅ Everything in mini + cloud, plus:
- ✅ **Intelligent finding verification** to filter false positives
- ✅ **Advanced risk scoring** (0-100 normalized scale)
- ✅ **Multi-format reporting** (Text, JSON, HTML, Markdown)
- ✅ **Passive intelligence** integration (Shodan, VirusTotal, SecurityTrails)
- ✅ **Extensive S3 bucket enumeration** (40+ patterns)
- ✅ **Comprehensive port scanning** (20+ services)
- ✅ **Four scan modes** (Safe, Normal, Aggressive, Stealth)
- ✅ **Performance optimized** with connection pooling & caching

**Performance Optimizations (No API Keys Required):**
-  **3-5x faster** than previous versions
-  **50% less memory** usage via session reuse
-  **Connection pooling** with DNS/SSL caching
-  **Parallel scanning** for files, buckets, and ports
-  See [PERFORMANCE_IMPROVEMENTS.md](/doc/PERFORMANCE_IMPROVEMENTS.md) for benchmarks

**Ideal For:**
- Professional security audits
- Compliance assessments
- Research and threat hunting
- Comprehensive reconnaissance

---

##  Feature Comparison

| Feature | Mini | Normal | Pro |
|---------|------|--------|-----|
| **Speed** | 3-5s | 10-20s | 8-15s |
| HTTP Security Headers | ✅ | ✅ | ✅ |
| SSL/TLS Validation | ✅ | ✅ | ✅ |
| DNS Records (SPF/DMARC) | ✅ | ✅ | ✅ |
| Sensitive Files | Basic | Enhanced | Comprehensive |
| CORS Analysis | ❌ | ✅ | ✅ |
| S3 Bucket Enum | ❌ | Basic | Extensive (40+) |
| Port Scanning | ❌ | Common | Full (20+) |
| Subdomain Takeover | ❌ | ✅ | ✅ |
| Finding Verification | ❌ | ❌ | ✅ |
| Risk Scoring | ❌ | ❌ | ✅ (0-100) |
| Multi-Format Reports | ❌ | ❌ | ✅ (4 formats) |
| API Integrations | ❌ | ❌ | ✅ (7 sources) |
| Scan Modes | 1 | 1 | 4 |
| Performance Cache | ❌ | ❌ | ✅ (DNS/SSL) |
| Connection Pooling | ❌ | ❌ | ✅ |

---

## 🛠️ Installation

### Prerequisites
- **Python 3.10+** (recommended)
- Virtual environment (venv/virtualenv)
- pip package manager

### Basic Installation

```bash
# Clone repository
git clone https://github.com/RicheByte/cloudMonkey.git
cd cloudMonkey

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install -U pip
pip install -r requirements.txt
```

### Verify Installation

```bash
# Test mini scanner
python cloud-mini.py --help

# Test normal scanner
python cloud.py --help

# Test pro scanner
python cloud-pro.py --help
```

---

##  Usage Examples

### Basic Scans

```bash
# Quick scan with mini
python cloud-mini.py example.com

# Balanced scan with normal
python cloud.py example.com

# Professional scan
python cloud-pro.py example.com
```

### cloud-pro.py Advanced Usage

#### Scan Modes

```bash
# Safe mode (non-intrusive, minimal impact)
python cloud-pro.py example.com --mode safe

# Normal mode (standard security scanning)
python cloud-pro.py example.com --mode normal

# Aggressive mode (deep scanning with active probing)
python cloud-pro.py example.com --mode aggressive

# Stealth mode (evasion techniques, reduced footprint)
python cloud-pro.py example.com --mode stealth
```

#### Output Formats

```bash
# HTML report (interactive)
python cloud-pro.py example.com --format html -o report.html

# JSON (machine-readable)
python cloud-pro.py example.com --format json -o results.json

# Markdown (documentation)
python cloud-pro.py example.com --format markdown -o report.md

# Text (default, human-readable)
python cloud-pro.py example.com --format text -o report.txt
```

#### Advanced Options

```bash
# Enable finding verification (filter false positives)
python cloud-pro.py example.com --verify

# Disable verification (faster but less accurate)
python cloud-pro.py example.com --no-verify

# Verbose output
python cloud-pro.py example.com -v

# Custom timeout (seconds)
python cloud-pro.py example.com --timeout 15

# Adjust concurrent workers
python cloud-pro.py example.com --workers 100

# Generate API configuration template
python cloud-pro.py --generate-config
```

#### With API Integration

```bash
# Using config file for API keys
python cloud-pro.py example.com --config api_config.json

# Full scan with all features
python cloud-pro.py example.com \
  --mode aggressive \
  --verify \
  --config api_config.json \
  --format html \
  -o comprehensive_report.html \
  -v
```

---

##  Configuration

### Environment Variables

For API integrations (optional, cloud-pro.py only):

```bash
# Shodan
export SHODAN_API_KEY="your_shodan_key"

# Censys
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"

# SecurityTrails
export SECURITYTRAILS_API_KEY="your_securitytrails_key"

# VirusTotal
export VIRUSTOTAL_API_KEY="your_virustotal_key"

# Hunter.io
export HUNTER_API_KEY="your_hunter_key"

# URLScan
export URLSCAN_API_KEY="your_urlscan_key"

# AlienVault OTX
export ALIENVAULT_API_KEY="your_alienvault_key"
```

### API Configuration File

Generate a template:

```bash
python cloud-pro.py --generate-config
```

This creates `api_config_template.json`:

```json
{
  "apis": {
    "shodan": {
      "api_key": "YOUR_SHODAN_API_KEY",
      "enabled": false
    },
    "censys": {
      "api_id": "YOUR_CENSYS_API_ID",
      "api_secret": "YOUR_CENSYS_API_SECRET",
      "enabled": false
    },
    "virustotal": {
      "api_key": "YOUR_VIRUSTOTAL_API_KEY",
      "enabled": false
    }
  }
}
```

Edit the file with your keys and set `"enabled": true` for APIs you want to use.

---

##  Output & Reporting

### Risk Scoring (cloud-pro.py)

cloudMonkey Pro uses a **normalized 0-100 risk score**:

| Score Range | Severity | Icon | Description |
|-------------|----------|------|-------------|
| 90-100 | CRITICAL | 🔴 | Immediate action required |
| 70-89 | HIGH | 🟠 | Significant security risk |
| 40-69 | MEDIUM | 🟡 | Moderate concern |
| 10-39 | LOW | 🟢 | Minor issue |
| 0-9 | INFO | 🔵 | Informational |

### Report Formats

**Text Report:**
```
╔═══════════════════════════════════════════╗
║    CLOUD SECURITY SCANNER - REPORT        ║
╚═══════════════════════════════════════════╝

 SCAN SUMMARY
Target: example.com
Risk Score: 75/100 (HIGH)
Findings: 23
...
```

**HTML Report:**
- Interactive dashboard
- Color-coded severity levels
- Expandable finding details
- Professional styling

**JSON Report:**
- Machine-readable structure
- Integration-friendly
- Programmatic analysis

**Markdown Report:**
- Documentation-ready
- GitHub/GitLab compatible
- Easy to version control

---

##  Understanding Findings

### Finding Structure

Each security finding includes:

```python
{
  "type": "MISSING_HSTS",           # Finding type
  "severity": "HIGH",                # Risk level
  "location": "https://example.com", # Where found
  "description": "...",              # What it means
  "evidence": "...",                 # Proof
  "confidence": "HIGH",              # How certain
  "remediation": "...",              # How to fix
  "verified": true,                  # Was it verified?
  "risk_score": 75,                  # Individual score
  "timestamp": "2025-10-29T..."      # When found
}
```

### Common Finding Types

**HTTP Security:**
- `MISSING_HSTS` - No HTTP Strict Transport Security
- `MISSING_CSP` - No Content Security Policy
- `MISSING_X_FRAME_OPTIONS` - Clickjacking risk
- `INSECURE_COOKIE` - Cookies without Secure flag

**SSL/TLS:**
- `SSL_CERTIFICATE_EXPIRED` - Certificate expired
- `SSL_CERTIFICATE_EXPIRING` - Expires within 30 days
- `WEAK_TLS_VERSION` - Using TLS 1.0/1.1 or SSL

**Cloud Services:**
- `S3_BUCKET_PUBLIC` - Publicly accessible S3 bucket
- `EXPOSED_SERVICE_PORT` - Open database/admin ports
- `SUBDOMAIN_TAKEOVER_RISK` - Dangling DNS records

**Configuration:**
- `SENSITIVE_FILE_EXPOSED` - .env, .git, config files accessible
- `PERMISSIVE_CORS` - CORS allows all origins
- `DIRECTORY_LISTING` - Directory browsing enabled

---

##  Performance Tips

### Optimize Scan Speed

```bash
# Fast network (low latency)
python cloud-pro.py example.com --workers 100 --timeout 5

# Slow network (high latency)
python cloud-pro.py example.com --workers 30 --timeout 15

# Maximum speed (safe mode)
python cloud-pro.py example.com --mode safe --workers 50
```

### Cache Benefits

cloudMonkey Pro automatically caches:
- **DNS lookups** - 5 minute TTL
- **SSL certificates** - 5 minute TTL
- **Connection pools** - Reused within scan

**Result:** 3-5x faster scans with no configuration needed!

---

##  Development

### Setting Up Dev Environment

```bash
git clone https://github.com/RicheByte/cloudMonkey.git
cd cloudMonkey
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: Install dev dependencies
# pip install pytest pytest-asyncio black flake8 mypy
```

### Running Tests

```bash
# Test individual scanners
python cloud-mini.py test.com
python cloud.py test.com
python cloud-pro.py test.com --mode safe
```

### Code Style

```bash
# Format code (if black installed)
black *.py

# Lint code (if flake8 installed)
flake8 *.py

# Type check (if mypy installed)
mypy cloud-pro.py
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

**Guidelines:**
- Keep changes focused and atomic
- Add tests for new features
- Update documentation
- Follow existing code style
- Ensure backwards compatibility

---

##  Roadmap

### Planned Features

- [ ] **Provider-specific modules**
  - AWS-specific checks (IAM, S3, EC2, Lambda)
  - Azure resource scanning
  - GCP configuration analysis
  
- [ ] **Enhanced Detection**
  - Machine learning for anomaly detection
  - Behavioral analysis patterns
  - Custom rule engine
  
- [ ] **Advanced Reporting**
  - PDF export
  - Executive summary generation
  - Trend analysis across scans
  
- [ ] **Integration & Automation**
  - GitHub Actions workflow
  - CI/CD pipeline templates
  - Slack/Discord notifications
  - JIRA ticket creation
  
- [ ] **Performance**
  - HTTP/2 support
  - Distributed scanning
  - Result streaming
  
- [ ] **Compliance**
  - OWASP Top 10 mapping
  - CIS benchmarks
  - PCI-DSS checks
  - GDPR compliance validation

---

##  Legal & Responsible Use

### Important Notice

**Only scan systems, networks, and applications that you own or have explicit written permission to assess.**

### Legal Compliance

- ✅ Obtain proper authorization before scanning
- ✅ Follow all applicable laws and regulations
- ✅ Respect terms of service and acceptable use policies
- ✅ Document your authorization and scope
- ✅ Report findings responsibly

### Prohibited Uses

- ❌ Scanning without permission
- ❌ Malicious exploitation of findings
- ❌ Disrupting services or systems
- ❌ Accessing unauthorized data
- ❌ Violating privacy laws

### Disclaimer

This tool is provided for **educational and authorized security assessment purposes only**. The authors and contributors:
- Are NOT responsible for misuse or damages
- Do NOT endorse illegal or unauthorized activities
- Provide NO warranties or guarantees
- Recommend proper training and certification for professional use

**Use at your own risk. You are responsible for your actions.**

---

##  Resources

### Security Learning

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### API Documentation

- [Shodan](https://developer.shodan.io/)
- [Censys](https://search.censys.io/api)
- [VirusTotal](https://developers.virustotal.com/)
- [SecurityTrails](https://securitytrails.com/corp/api)

### Related Tools

- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Amass](https://github.com/OWASP/Amass)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Nmap](https://nmap.org/)

---

##  Acknowledgments

Special thanks to:
- The cloud security research community
- CTF challenge creators and platforms
- Open-source contributors
- Bug bounty hunters sharing knowledge
- Security researchers advancing the field

---

##  License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 RicheByte

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

##  Contact & Support

- **Author:** RicheByte
- **Repository:** [github.com/RicheByte/cloudMonkey](https://github.com/RicheByte/cloudMonkey)
- **Issues:** [GitHub Issues](https://github.com/RicheByte/cloudMonkey/issues)

### Getting Help

1. Check the documentation in this README
2. Review [PERFORMANCE_IMPROVEMENTS.md](PERFORMANCE_IMPROVEMENTS.md)
3. Search existing [GitHub Issues](https://github.com/RicheByte/cloudMonkey/issues)
4. Open a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)
   - Relevant logs or output

---

**Made with ❤️ by RicheByte | Happy Hunting! 🐵**


Suggested commit and PR guidelines:
- Keep changes small and focused
- Add or update tests for new behavior
- Document flags and config changes
- For model changes, update the profile documentation above

## Roadmap ideas

- Provider-specific modules with pluggable discovery steps
- Expanded rule sets for misconfiguration detection
- Caching and resumable scans for large targets
- Rich output formats and export to common platforms
- Benchmarks for all three models

## Responsible and legal use

Only scan systems, accounts, and data that you own or have explicit permission to assess. Follow all applicable laws, terms of service, and organizational policies. The authors and contributors are not responsible for misuse or damages arising from the use of this tool.


## Acknowledgments

Thanks to the cloud security and CTF communities whose research and challenges inspire tooling like cloudMonkey.


