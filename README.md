# Custom Reconnaissance Tool

A modular penetration testing reconnaissance tool designed for automated information gathering during security assessments and bug bounty engagements.

The tool follows a real-world reconnaissance methodology and focuses on:

- Robust execution
- Clear output
- Professional HTML reporting
- Graceful handling of errors and rate limits

---

## Features

### Passive Reconnaissance

- **WHOIS Lookup**
  - Domain registration information
- **DNS Enumeration**
  - A, AAAA, MX, NS, TXT, and SOA records
- **Basic Subdomain Discovery**
  - Lightweight passive subdomain enumeration
- **Advanced Subdomain Discovery**
  - Multiple passive intelligence sources:
    - crt.sh
    - HackerTarget
    - AlienVault OTX (may be rate-limited)
    - URLScan.io
  - Some sources may be unavailable or rate-limited (e.g. OTX 429, ThreatCrowd SSL issues)

---

### Active Reconnaissance

- **Port Scanning**
  - Multi-threaded TCP port scanning
- **Banner Grabbing**
  - Service and version identification
- **Technology Detection**
  - Web server, CMS, and framework detection
- **Screenshot Capture**
  - Full-page screenshots using Playwright
  - Automatic HTTPS → HTTP fallback
  - Safe handling of timeouts and blocked targets

---

### Reporting

- Professional **HTML report**
- Includes:
  - Target and timestamp
  - Passive and active recon results
  - Advanced subdomain breakdown by source
  - Screenshots (if captured)
- Clean, color-coded, and easy-to-read format

---

## Installation

### Prerequisites

- Python **3.7+**

---

### Setup

1. **Clone the repository**

```
git clone https://github.com/dhaliaeid/recon-tool.git
cd recon-tool
```

2. **Create and activate a virtual environment**

```
python3 -m venv venv
source venv/bin/activate
```

3. **Install Python dependencies**

```
pip install -r requirements.txt
```

### Usage

#### Basic Commands

##### Run all reconnaissance modules

```
python recon.py --target example.com --all
python recon.py -t example.com --all
```

##### Passive reconnaissance only

```
python recon.py --target example.com --passive
```

#### Run Specific Modules

```
# WHOIS lookup
python recon.py --target example.com --whois

# DNS enumeration
python recon.py --target example.com --dns

# Basic subdomain discovery
python recon.py --target example.com --subdomains

# Advanced subdomain discovery
python recon.py --target example.com --subdomains-advanced

# Port scanning
python recon.py --target example.com --port-scan

# Banner grabbing (requires port scan)
python recon.py --target example.com --port-scan --banner

# Technology detection
python recon.py --target example.com --tech

# Screenshot capture
python recon.py --target example.com --screenshot
```

#### Combine Multiple Modules

```
python recon.py --target example.com --dns --subdomains --tech
```

#### Advanced Options

Custom Port Range

```
python recon.py --target example.com --port-scan --ports 1-65535
```

Scan Specific Ports

```
python recon.py --target example.com --port-scan --ports 80,443,8080,8443
```

Custom Output File

```
python recon.py --target example.com --all -o report_name

python recon.py --target example.com --all --output report_name
```

#### Verbosity Levels

```
# Default output
python recon.py --target example.com --all

# Info level logging
python recon.py --target example.com --all -v

# Debug level logging
python recon.py --target example.com --all -vv
```

## Project Structure

recon-tool/
├── recon.py # Main entry point
├── requirements.txt # Python dependencies
├── README.md # Documentation
└── modules/
├── **init**.py # Package initializer
├── whois.py # WHOIS lookup
├── dnsEnum.py # DNS enumeration
├── subdomain.py # Basic subdomain discovery
├── subdomains_advanced.py # Advanced subdomain discovery
├── portScan.py # Port scanning
├── bannerGrabber.py # Banner grabbing
├── techDetector.py # Technology detection
├── screenshots.py # Screenshot module (Playwright)
└── generateReport.py # HTML report generator

## Notes & Limitations

Some passive sources may:

Be rate-limited (HTTP 429)

Temporarily fail due to SSL or availability issues

Screenshot capture may fail if:

The target blocks headless browsers

The site is extremely slow or unreachable
In such cases, the tool continues without crashing and reports the failure.

## Purpose

This tool is designed for:
Read team bounty reconnaissance
Penetration testing reconnaissance
Bug bounty reconnaissance
Security learning and tooling practice
It follows a real-world recon methodology and emphasizes robustness, clarity, and reporting quality
