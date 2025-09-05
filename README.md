# Consent Risk Tracker – Browser Permissions & Cookie Auditor
A comprehensive browser-powered system that helps users audit, track, and manage their digital privacy footprint by analyzing browser cookies and permissions data.

![image alt](https://github.com/jetsu03/CONSENT-RISK-TRACKER/blob/main/Graphs.jpg)

## Overview
Modern web users often unknowingly grant sensitive permissions and cookie consent to websites while browsing online. This poses significant data privacy risks, especially for users in **Financial, Health, Nuclear Energy, and Consulting sectors** who may inadvertently provide access to sensitive data.
This solution provides complete visibility and control over browser permissions and cookies through automated extraction, risk analysis, and interactive dashboards.

## Why This Matters
- **Hidden Permissions**: Users grant camera, location, microphone access without tracking
- **Cookie Proliferation**: Hundreds of tracking cookies accumulate over time
- **Third-Party Risks**: External domains gain access to sensitive user data
- **Compliance Requirements**: Organizations need audit trails for privacy regulations
- **Security Vulnerabilities**: Stale permissions create attack vectors for hackers

## Features
### Data Extraction
- Extracts browser cookies from local Chrome profile
- Retrieves permission metadata (camera, location, notifications, etc.)
- Captures website trust scores and access patterns
- Identifies third-party vs first-party cookies

### Risk Assessment
- **Rule-based risk scoring** categorizing cookies as High/Medium/Low
- Frequency-based analysis (frequent sites = higher risk)
- Age-based scoring (older cookies = potential security risks)
- Third-party tracking identification

### Visualization & Reporting
- Interactive Power BI dashboard with multiple views
- Risk trend analysis and domain-specific insights
- Permission usage patterns by browser type
- Privacy score calculations and alerts

### Data Management
- Structured Excel workbook for easy management
- Automated data refresh and historical tracking
- Export capabilities for compliance reporting

## Tech Stack
- **Python 3.8+**
- **Google Chrome** (with local profile access)
- **Microsoft Excel** 2016 or later
- **Power BI Desktop** (free version available)
- **Windows/macOS/Linux** support

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/consent-risk-tracker.git
cd consent-risk-tracker
```

### 2. Install Dependencies in virtual environment
```bash
pip install -r requirements.txt
```

### 3. Setup Chrome Profile Access
```bash
# Locate your Chrome profile directory
# Windows: %USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default
# macOS: ~/Library/Application Support/Google/Chrome/Default
# Linux: ~/.config/google-chrome/Default
```

### 4. Extract Browser Data
```bash
python cookies.py
```
This script will:
- Scan your Chrome profile for cookies and permissions
- Extract metadata including domains, timestamps, and access counts
- Generate raw data files for processing

### Excel Report Sheets
1. **Cookie Data** - Complete cookie listing with risk scores
2. **Permissions Data** - Granted permissions by domain
3. **Risk Summary** - Aggregated risk metrics
4. **Historical Trends** - Time-based analysis
5. **Action Items** - Recommended privacy actions
