# WEB_APP_SECURITY_SCANNER

*Streamlining Security Testing for Seamless Web Application Protection*

![last commit](https://img.shields.io/github/last-commit/farisahmed123/Web-App-Security-Scanner)
![Python](https://img.shields.io/badge/python-100.0%25-blue)
![languages](https://img.shields.io/github/languages/count/farisahmed123/Web-App-Security-Scanner)

Built with the tools and technologies:

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Output Files](#output-files)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

**Web App Security Scanner** is an educational Python-based tool designed to help developers and security professionals identify SQL injection vulnerabilities in web applications. With a simple command-line interface and automated CSV reporting, this tool makes security testing accessible and actionable.

### Why Use This Tool?

- 🎯 **Easy to Use**: Simple command-line interface - no complex configurations
- 📊 **Detailed Reports**: Automatic CSV generation with vulnerability details and fix recommendations
- 🎓 **Educational**: Clear code structure perfect for learning security testing concepts
- 🚀 **Fast**: Efficiently tests multiple URLs and parameters
- 💡 **Actionable**: Provides specific code examples to fix discovered vulnerabilities

---

## Features

| Feature | Description |
|---------|-------------|
| **Automated Testing** | Test single URLs or batch process multiple endpoints from a file |
| **SQL Injection Detection** | Identifies common SQL injection patterns using curated payloads |
| **Smart Detection** | Analyzes response patterns, error messages, and HTTP status codes |
| **CSV Reporting** | Generates comprehensive reports with timestamps, payloads, and solutions |
| **Color-Coded Output** | Easy-to-read terminal output with vulnerability status |
| **Fix Suggestions** | Provides code examples showing how to remediate each vulnerability |
| **Payload Customization** | Easily add or modify test payloads via `payloads.txt` |

---

## Getting Started

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/farisahmed123/Web-App-Security-Scanner.git
   cd Web-App-Security-Scanner
   ```

2. **Install required dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python sqli_tester_enhanced.py --help
   ```

---

## Usage

### Test a Single URL

```bash
python sqli_tester_enhanced.py "http://localhost:8000/api/rides/?id=1&date=2025-11-22"
```

### Test Multiple URLs from File

1. Create a `urls.txt` file with your target URLs:
   ```
   http://localhost:8000/api/rides/?id=1
   http://localhost:8000/api/users/?email=test@example.com
   http://localhost:8000/api/search/?query=test
   ```

2. Run the scanner:
   ```bash
   python sqli_tester_enhanced.py -f urls.txt
   ```

### Example Output

```
⚠ Legal Warning: Only test your own applications!

✓ Loaded 57 test payloads

============================================================
Testing: http://localhost:8000/api/rides/?date=2025-11-22
============================================================

→ Testing: date
✗ VULNERABLE!
  Payload: ' OR '1'='1
  Error: postgresql

------------------------------------------------------------
⚠ Found 1 vulnerability(ies)
------------------------------------------------------------

✓ Report saved: ShareCare_Vulnerability_Report.csv
```

---

## Project Structure

```
Web-App-Security-Scanner/
│
├── sqli_tester_enhanced.py    # Main scanner script
├── payloads.txt                # SQL injection test payloads
├── urls.txt                    # Target URLs for batch testing
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
└── ShareCare_Vulnerability_Report.csv  # Generated report (after scan)
```

---

## How It Works

### 1. **Payload Loading**
The scanner loads SQL injection payloads from `payloads.txt`, which includes:
- Authentication bypass attempts
- UNION-based injections
- Error-based detection strings
- Time-based blind injection tests
- WAF evasion techniques

### 2. **Vulnerability Detection**
For each parameter in the URL, the scanner:
- Sends HTTP requests with injected payloads
- Analyzes responses for SQL error keywords
- Checks for database-specific error messages
- Monitors response patterns and anomalies

### 3. **Report Generation**
When vulnerabilities are found, the tool:
- Records timestamp, URL, parameter, and payload
- Identifies the error type (e.g., PostgreSQL, MySQL)
- Generates fix recommendations with code examples
- Exports everything to a CSV file

---

## Output Files

### CSV Report Format

| Column | Description |
|--------|-------------|
| `time` | Timestamp when vulnerability was found |
| `url` | Full URL that was tested |
| `parameter` | Vulnerable parameter name |
| `payload` | SQL injection payload that succeeded |
| `error_type` | Type of SQL error detected |
| `solution` | Code examples showing how to fix |

### Sample CSV Output

```csv
time,url,parameter,payload,error_type,solution
2025-11-23 14:30:22,http://localhost:8000/api/rides/?date=2025-11-22,date,' OR '1'='1,postgresql,"HOW TO FIX: Use parameterized queries..."
```

---

## Configuration

### Customizing Payloads

Edit `payloads.txt` to add your own test strings:

```
# Authentication Bypass
' OR '1'='1
' OR 1=1--
admin'--

# UNION Injections
' UNION SELECT NULL--
' UNION SELECT 1,2,3--

# Add your custom payloads here
```

### Customizing Target URLs

Edit `urls.txt` to define your test targets:

```
# API Endpoints
http://localhost:8000/api/rides/?id=1
http://localhost:8000/api/users/?email=test@example.com

# Add more URLs here
```

---

## Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the branch** (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

### Ideas for Contributions
- Add support for other injection types (XSS, Command Injection)
- Implement multithreading for faster scans
- Add JSON/HTML report formats
- Create a web-based GUI
- Add authentication support for protected endpoints

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- **Created by**: Faris Ahmed (farisnizamani120@gmail.com)
- **Purpose**: Educational tool for learning web application security testing
- **Inspiration**: Built to help developers understand and prevent SQL injection vulnerabilities

### Disclaimer

⚠️ **LEGAL WARNING**: This tool is for educational purposes only. Only test applications you own or have explicit permission to test. Unauthorized testing of web applications is illegal and unethical.

---

## Support

If you found this project helpful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs via GitHub Issues
- 💡 Suggesting new features
- 📢 Sharing with others who might benefit

---

**Made with ❤️ for the security community**
