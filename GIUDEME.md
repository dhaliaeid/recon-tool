# 🚀 Complete Setup Guide

## Step-by-Step Installation

### Step 1: Create Project Directory

```bash
# Create main project folder
mkdir recon-tool
cd recon-tool

# Create modules subdirectory
mkdir modules
```

### Step 2: Create All Files

Create the following files in your project directory:

**File structure:**

```
recon-tool/
├── recon.py
├── requirements.txt
├── README.md
├── Dockerfile
└── modules/
    ├── __init__.py
    ├── whois_lookup.py
    ├── dns_enum.py
    ├── subdomain_enum.py
    ├── port_scanner.py
    ├── banner_grabber.py
    ├── tech_detector.py
    └── reporter.py
```

### Step 3: Copy the Code

Copy each code artifact I provided into its respective file:

1. **recon.py** - Main script
2. **requirements.txt** - Dependencies
3. **README.md** - Documentation
4. **Dockerfile** - Docker configuration
5. **modules/**init**.py** - Package initializer
6. **modules/whois_lookup.py** - WHOIS module
7. **modules/dns_enum.py** - DNS enumeration
8. **modules/subdomain_enum.py** - Subdomain discovery
9. **modules/port_scanner.py** - Port scanner
10. **modules/banner_grabber.py** - Banner grabber
11. **modules/tech_detector.py** - Technology detector
12. **modules/reporter.py** - Report generator

### Step 4: Install Dependencies

```bash
# Install required Python packages
pip install -r requirements.txt
```

Or install individually:

```bash
pip install dnspython==2.4.2
pip install requests==2.31.0
pip install urllib3==2.0.7
```

### Step 5: Test the Installation

```bash
# Check if it runs
python recon.py --help

# Test with a simple scan
python recon.py --target example.com --whois
```

---

## Quick Test Commands

### Test Individual Modules

```bash
# Test WHOIS (passive, safe)
python recon.py --target example.com --whois -v

# Test DNS (passive, safe)
python recon.py --target example.com --dns -v

# Test Subdomains (passive, safe)
python recon.py --target example.com --subdomains -v
```

### Test Active Modules (Use Your Own Domain!)

```bash
# Test port scan (only on domains you own!)
python recon.py --target yourdomain.com --port-scan --ports 80,443 -v

# Full test
python recon.py --target yourdomain.com --all -vv
```

---

## Testing with Safe Targets

You can safely test passive modules on these domains:

- `example.com` (official test domain)
- `scanme.nmap.org` (intentionally scannable)
- Your own domain

**Never scan:**

- Government websites
- Financial institutions
- Domains you don't own or have permission to test

---

## Creating a Test Report

```bash
# Generate a sample report for example.com
python recon.py --target example.com --passive -o example_report.html

# Open the report in your browser
# On Linux/Mac:
open example_report.html

# On Windows:
start example_report.html
```

---

## Docker Setup (Bonus)

### Build Docker Image

```bash
# Build the image
docker build -t recon-tool .

# Verify it was built
docker images | grep recon-tool
```

### Run with Docker

```bash
# Show help
docker run --rm recon-tool --help

# Run a scan and save report to current directory
docker run --rm -v $(pwd):/app/reports recon-tool \
  --target example.com \
  --passive \
  -o /app/reports/example_report.html

# Run full scan
docker run --rm -v $(pwd):/app/reports recon-tool \
  --target scanme.nmap.org \
  --all \
  -o /app/reports/scanme_report.html
```

---

## Troubleshooting

### Common Issues

**1. ImportError: No module named 'modules'**

Solution:

```bash
# Make sure __init__.py exists
touch modules/__init__.py
```

**2. ModuleNotFoundError: No module named 'dns'**

Solution:

```bash
pip install dnspython
```

**3. Permission denied when scanning**

Solution: Some port scans require elevated privileges

```bash
# On Linux/Mac (only if needed)
sudo python recon.py --target yourdomain.com --port-scan
```

**4. Slow port scanning**

Solution: Reduce port range

```bash
python recon.py --target example.com --port-scan --ports 1-100
```

**5. Docker volume mounting issues on Windows**

Solution: Use full path

```bash
docker run --rm -v C:\Users\YourName\recon-tool:/app/reports recon-tool --target example.com --passive
```

---

## GitHub Repository Setup

### Initialize Git Repository

```bash
# Initialize git
git init

# Create .gitignore
cat > .gitignore << EOF
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info/
dist/
build/
*.html
*.txt
!requirements.txt
.vscode/
.idea/
EOF

# Add files
git add .

# Commit
git commit -m "Initial commit: Custom Reconnaissance Tool"
```

### Push to GitHub

```bash
# Create repository on GitHub first, then:
git remote add origin https://github.com/yourusername/recon-tool.git
git branch -M main
git push -u origin main
```

---

## Code Quality Checks

### Before Submitting

```bash
# Check Python syntax
python -m py_compile recon.py
python -m py_compile modules/*.py

# Test all modules
python recon.py --target example.com --all -vv

# Generate sample report
python recon.py --target example.com --passive -o sample_report.html
```

---

## Deliverables Checklist

- [ ] All code files created and working
- [ ] README.md completed with usage examples
- [ ] requirements.txt includes all dependencies
- [ ] Sample report generated (example.com or scanme.nmap.org)
- [ ] Code commented and documented
- [ ] GitHub repository created (public or private)
- [ ] Dockerfile created (bonus)
- [ ] Docker image builds successfully (bonus)
- [ ] All modules tested individually
- [ ] Full integration test completed
- [ ] .gitignore configured properly

---

## Next Steps

1. **Test thoroughly** - Try all modules and flags
2. **Document your testing** - Take screenshots
3. **Create sample reports** - For different targets
4. **Add features** - Get creative with bonus functionality
5. **Polish documentation** - Make it professional
6. **Prepare presentation** - Be ready to demo

---

## Advanced Features to Consider

- [ ] Multiple target support (scan multiple domains)
- [ ] JSON output format option
- [ ] Save results to database (SQLite)
- [ ] Progress bars for long scans
- [ ] Email report delivery
- [ ] Integration with threat intelligence APIs
- [ ] Comparison mode (track changes over time)
- [ ] Web dashboard (Flask/Django)

---

## Resources

- **Python Documentation**: https://docs.python.org/3/
- **dnspython**: https://dnspython.readthedocs.io/
- **requests**: https://requests.readthedocs.io/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Penetration Testing Framework**: http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html

---

## Need Help?

If you encounter issues:

1. Check the troubleshooting section
2. Review error messages carefully
3. Test modules individually
4. Check Python and package versions
5. Consult documentation

Good luck with your project! 🚀
