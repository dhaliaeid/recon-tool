# 🔍 Custom Reconnaissance Tool

A modular penetration testing reconnaissance tool designed for automated information gathering during security assessments.

## 📋 Features

### Passive Reconnaissance

- **WHOIS Lookup**: Domain registration information
- **DNS Enumeration**: A, AAAA, MX, NS, TXT, and SOA records
- **Subdomain Discovery**: Using certificate transparency logs (crt.sh)

### Active Reconnaissance

- **Port Scanning**: Multi-threaded TCP port scanning
- **Banner Grabbing**: Service identification
- **Technology Detection**: Web server and framework identification

### Reporting

- Professional HTML reports with all findings
- Timestamps and IP resolution details
- Color-coded, easy-to-read format

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. **Clone or download the repository**

```bash
git clone https://github.com/dhaliaeid/recon-tool.git
cd recon-tool
```

2. **Create project structure**

```
recon-tool/
├── recon.py
├── requirements.txt
├── README.md
└── modules/
    ├── __init__.py
    ├── whois.py
    ├── dnsEnum.py
    ├── subdomain.py
    ├── portScan.py
    ├── bannerGrabber.py
    ├── techDetector.py
    └── genrateReport.py
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Create modules/**init**.py**

```bash
mkdir modules
touch modules/__init__.py
```

## 📖 Usage

### Basic Commands

**Run all reconnaissance modules:**

```bash
python recon.py --target example.com --all
```

**Passive reconnaissance only:**

```bash
python recon.py --target example.com --passive
```

**Specific modules:**

```bash
# WHOIS lookup only
python recon.py --target example.com --whois

# DNS enumeration
python recon.py --target example.com --dns

# Subdomain discovery
python recon.py --target example.com --subdomains

# Port scanning
python recon.py --target example.com --port-scan

# Banner grabbing (requires port scan)
python recon.py --target example.com --port-scan --banner

# Technology detection
python recon.py --target example.com --tech
```

**Combine multiple modules:**

```bash
python recon.py --target example.com --dns --subdomains --tech
```

### Advanced Options

**Custom port range:**

```bash
python recon.py --target example.com --port-scan --ports 1-65535
```

**Specific ports:**

```bash
python recon.py --target example.com --port-scan --ports 80,443,8080,8443
```

**Custom output file:**

```bash
python recon.py --target example.com --all -o my_report.html
```

**Verbosity levels:**

```bash
# Basic output
python recon.py --target example.com --all

# Verbose (info level)
python recon.py --target example.com --all -v

# Very verbose (debug level)
python recon.py --target example.com --all -vv
```

### Complete Example

```bash
python recon.py --target example.com --all -vv -o example_report.html
```

This will:

- Run all reconnaissance modules
- Use maximum verbosity
- Save results to `example_report.html`

## 📊 Sample Output

```
============================================================
  Custom Reconnaissance Tool
  Target: example.com
  Time: 2024-01-15 14:30:22
============================================================

[*] Running WHOIS lookup...
    [+] WHOIS lookup completed
[*] Running DNS enumeration...
    [+] Found 12 DNS records
[*] Running subdomain enumeration...
    [+] Found 45 subdomains
[*] Running port scan...
    [*] Scanning 1000 ports... (this may take a while)
    [+] Port 80/tcp is OPEN
    [+] Port 443/tcp is OPEN
    [+] Scan complete: 2 open port(s) found
[*] Running banner grabbing...
    [+] Port 80: HTTP/1.1 200 OK...
    [+] Port 443: HTTP/1.1 200 OK...
[*] Running technology detection...
    [+] Server: nginx/1.18.0
    [+] Technologies found: 3

[*] Generating report: report_example_com_20240115_143025.html
[+] Report saved to: report_example_com_20240115_143025.html

============================================================
  Reconnaissance Complete!
============================================================
```

## 🏗️ Project Structure

```
recon-tool/
├── recon.py              # Main script
├── requirements.txt      # Python dependencies
├── README.md            # This file
└── modules/
    ├── __init__.py          # Package initializer
    ├── whois_lookup.py      # WHOIS module
    ├── dns_enum.py          # DNS enumeration
    ├── subdomain_enum.py    # Subdomain discovery
    ├── portScan.py      # Port scanning
    ├── bannerGrabber.py    # Banner grabbing
    ├── techDetector.py     # Technology detection
    └── generateReport.py          # HTML report generator
```

## 🐳 Docker Deployment

**Create Dockerfile:**

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "recon.py"]
```

**Build and run:**

```bash
# Build image
docker build -t recon-tool .

# Run scan
docker run --rm recon-tool --target example.com --all
```

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for educational and authorized penetration testing only.

- Only scan systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- The developers assume no liability for misuse of this tool
- Always obtain written authorization before testing

## 🔧 Troubleshooting

**Issue: "Module not found" error**

```bash
# Ensure modules/__init__.py exists
touch modules/__init__.py
```

**Issue: Port scan takes too long**

```bash
# Reduce port range
python recon.py --target example.com --port-scan --ports 1-100
```

**Issue: DNS resolution fails**

```bash
# Check internet connection
# Try with IP address instead
python recon.py --target 93.184.216.34 --port-scan
```

## 📝 Development

### Adding New Modules

1. Create new module in `modules/` directory
2. Implement main function that returns a dictionary
3. Import in `recon.py`
4. Add command-line flag
5. Update README

### Code Quality

- Use meaningful variable names
- Add docstrings to functions
- Implement error handling
- Log important events
- Follow PEP 8 style guide

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is for educational purposes. Use responsibly.

## 👥 Authors

- Your Name - Initial work

## 🙏 Acknowledgments

- OWASP for reconnaissance guidelines
- Python community for excellent libraries
- Certificate transparency logs (crt.sh)
