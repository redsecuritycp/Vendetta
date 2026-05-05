# replit.md

## Overview

This repository contains two security-focused Python tools:

1. **Load Test Tool** (`load_test/`): A load testing utility with both CLI and Streamlit web interface for stress-testing web applications. Uses async HTTP requests via aiohttp to generate high-concurrency traffic.

2. **Web Audit Safe** (`web_audit_safe/`): A passive security auditing tool for web applications. Performs non-intrusive security analysis including header checks, TLS verification, cookie security, CSRF detection, and CORS configuration analysis.

Both tools include prominent legal disclaimers emphasizing authorized use only.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Load Test Tool (`load_test/`)

- **Async Engine Pattern**: Core load testing logic in `load_test_engine.py` using asyncio and aiohttp for high-concurrency HTTP requests
- **Dual Interface**: CLI via `main.py` and web GUI via Streamlit in `app.py`
- **Configuration**: Environment variables via python-dotenv for target URL, concurrency limits, and duration
- **Real-time Metrics**: Queue-based results collection for live statistics (RPS, latency, success/error rates)
- **Concurrency Control**: Semaphore-based limiting to control maximum concurrent requests

### Web Audit Safe (`web_audit_safe/`)

- **Package Structure**: Installable Python package with `src/` layout and setuptools configuration
- **Modular Checks**: Security checks organized in `checks/` module:
  - `headers.py`: HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
  - `tls.py`: SSL/TLS certificate validation
  - `cookies.py`: Cookie security flags (Secure, HttpOnly, SameSite)
  - `forms.py`: CSRF protection and form security
  - `cors.py`: CORS misconfiguration detection
  - `exposure.py`: Common file exposure (robots.txt, .git, etc.)
- **BFS Crawler**: Rate-limited web crawler respecting robots.txt
- **Report Generation**: Outputs both JSON and Markdown reports with evidence collection
- **CLI Interface**: Rich library for formatted terminal output with progress indicators

### Root Application

- **Streamlit Web Interface**: Main application entry point via `streamlit_app.py` on port 5000
- **Load Test Engine**: Core async engine in `load_test_engine.py` for HTTP load testing
- **Flask Health Check**: Minimal Flask app in `main.py` for deployment health checks

### Security Testing Modules

- **sslstrip_sim.py**: HSTS/SSLStrip vulnerability analyzer - detects missing HSTS headers and SSL downgrade risks
- **xss_test.py**: XSS vulnerability detector - tests URL parameters for reflected XSS vulnerabilities
- **recon.py**: Passive reconnaissance tool - gathers public information (DNS, SSL, technologies, security headers)
- **clickjacking_test.py**: Clickjacking vulnerability checker - tests X-Frame-Options and CSP frame-ancestors
- **exploit_demo.py**: PoC generator - creates downloadable HTML demos for clickjacking attacks and XSS payloads to visually demonstrate vulnerability impact
- **slowloris.py**: Slowloris attack simulator - slow HTTP attack that bypasses rate limiting and traditional firewalls
- **dir_fuzzer.py**: Directory/file fuzzer - discovers exposed files (.git, .env, backups, admin panels, config files)
- **form_analyzer.py**: Form security analyzer - detects CSRF vulnerabilities and input validation issues
- **subdomain_enum.py**: Subdomain enumerator - finds less-protected subdomains (dev, staging, admin, api)
- **bypass_403.py**: 403 Bypass tool - attempts to bypass 403 Forbidden protections using backup variants, URL encoding, header manipulation, and path tricks

## External Dependencies

### Load Test Tool
- `aiohttp`: Async HTTP client for high-performance requests
- `streamlit`: Web-based GUI framework
- `plotly`: Interactive charts for real-time metrics visualization
- `python-dotenv`: Environment variable management

### Web Audit Safe
- `requests`: Synchronous HTTP client for crawling
- `beautifulsoup4`: HTML parsing for form and link extraction
- `cryptography`: TLS/SSL certificate analysis
- `rich`: Terminal formatting and progress display
- `urllib3`: HTTP utilities and connection pooling

### Root Application
- `flask`: Lightweight web framework for the main entry point
- `streamlit`: Web-based GUI framework
- `plotly`: Interactive charts for real-time metrics
- `aiohttp`: Async HTTP client for load testing