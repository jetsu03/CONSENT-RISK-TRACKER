# Consent Risk Tracker – Browser Permissions & Cookie Auditor
A comprehensive browser-powered system that helps users audit, track, and manage their digital privacy footprint by analyzing browser cookies and permissions data.

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

## Usage
### Step 1: Extract Browser Data
```bash
python extract_browser_data.py
```
This script will:
- Scan your Chrome profile for cookies and permissions
- Extract metadata including domains, timestamps, and access counts
- Generate raw data files for processing

### Step 2: Generate Risk Scores
```bash
python risk_assessment.py
```
Risk scoring algorithm considers:
- **Usage Frequency**: High-traffic sites = Higher risk
- **Cookie Age**: Older cookies = Potential security risk
- **Third-Party Status**: External trackers = Higher risk
- **Permission Types**: Sensitive permissions = Higher risk

### Step 3: Create Excel Report
```bash
python generate_excel_report.py
```
Outputs structured workbook with:
- Cookie inventory with risk classifications
- Permission audit trail
- Domain trust scores
- Historical tracking data

### Step 4: Launch Power BI Dashboard
1. Open `ConsentRiskTracker.pbix` in Power BI Desktop
2. Connect to the generated Excel workbook
3. Refresh data to load latest analysis
4. Explore interactive visualizations

## 📊 Dashboard Features

### Risk Matrix View
- **Security vs Privacy** risk intersections
- Color-coded by cookie age (fresh vs stale)
- Interactive filtering by browser and domain

### Top Risk Domains
- Ranked list of highest-risk websites
- Site trust scores and permission usage
- Third-party tracker identification

### Trend Analysis
- Cookie accumulation over time
- Permission grant patterns
- Browser-specific risk profiles

### Summary Metrics
- Overall privacy score
- High/Medium/Low risk distribution
- Third-party vs first-party breakdown

## ⚙️ Configuration

### Risk Scoring Rules (risk_config.json)
```json
{
  "frequency_thresholds": {
    "high": 100,
    "medium": 10,
    "low": 1
  },
  "age_thresholds": {
    "fresh": 30,
    "medium": 180,
    "stale": 365
  },
  "high_risk_permissions": [
    "camera",
    "microphone",
    "location",
    "notifications"
  ]
}
```

### Custom Risk Rules
Modify `risk_assessment.py` to implement organization-specific scoring:
```python
def calculate_domain_risk(domain, usage_count, last_access_days):
    # Custom risk logic here
    if domain in FINANCIAL_DOMAINS and usage_count > 50:
        return "HIGH"
    # Additional rules...
```

## 📁 Project Structure

```
consent-risk-tracker/
├── src/
│   ├── extract_browser_data.py      # Chrome data extraction
│   ├── risk_assessment.py           # Risk scoring engine
│   ├── generate_excel_report.py     # Excel workbook generator
│   └── utils/
│       ├── chrome_parser.py         # Chrome database parsing
│       ├── risk_calculator.py       # Risk scoring algorithms
│       └── excel_formatter.py       # Excel styling and formatting
├── data/
│   ├── raw/                         # Extracted browser data
│   ├── processed/                   # Risk-scored data
│   └── reports/                     # Generated Excel reports
├── dashboards/
│   └── ConsentRiskTracker.pbix      # Power BI dashboard file
├── config/
│   └── risk_config.json             # Risk scoring configuration
├── requirements.txt
├── README.md
└── LICENSE
```

## 🔧 Dependencies

```txt
pandas>=1.5.0
sqlite3
openpyxl>=3.0.10
python-dateutil>=2.8.2
cryptography>=3.4.8
pathlib2>=2.3.6
configparser>=5.3.0
logging>=0.4.9.6
```

## 📈 Sample Output

### Risk Assessment Results
```
Domain: hire.glider.ai
├── Trust Score: 2.1 (High Risk)
├── Last Access: 2024-10-27
├── Cookie Age: 312 days
├── Third Party: True
├── Permissions: ['notifications', 'location']
└── Risk Level: HIGH
```

### Excel Report Sheets
1. **Cookie Data** - Complete cookie listing with risk scores
2. **Permissions Data** - Granted permissions by domain
3. **Risk Summary** - Aggregated risk metrics
4. **Historical Trends** - Time-based analysis
5. **Action Items** - Recommended privacy actions

---

⭐ **Star this repository if it helped you manage your digital privacy!** ⭐
