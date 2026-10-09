# Blue Team SOC Lab: Authentication Log Detection

A hands-on cybersecurity project that uses Python and pandas to analyze authentication events, identify suspicious login patterns, and generate alerts for further investigation.

**Project status:** Initial working prototype

**Technologies:** Python 3.12, pandas, Git, GitHub

## Project Overview

Security Operations Center (SOC) analysts review authentication logs to identify potentially malicious activity, including repeated failed logins and successful authentication following multiple failures.

This project simulates that workflow using a fictional authentication dataset. A Python script analyzes the events, applies basic detection logic, and exports suspicious activity to a CSV report.

## Objectives

- Parse and analyze authentication events using Python and pandas.
- Detect repeated authentication failures within a five-minute window.
- Identify successful logins occurring shortly after repeated failures.
- Generate a structured CSV alert report.
- Practice security monitoring, alert triage, and detection engineering fundamentals.

## Project Structure

```text
blueteam-soc-lab/
├── data/
│   └── auth_events.csv
├── reports/
│   └── suspicious_events.csv
├── src/
│   └── analyze_logs.py
├── .gitignore
└── README.md
```

## Detection Logic

### 1. Repeated Authentication Failures

The script identifies five failed authentication events for the same username and source IP within a five-minute window.

**Why it matters:** Repeated failures may indicate a brute-force attempt, password guessing, or a user experiencing authentication problems.

### 2. Successful Login After Repeated Failures

After identifying the fifth failure, the script checks for a successful login from the same username and source IP within the following five minutes.

**Why it matters:** This sequence warrants investigation because it may indicate that an account was accessed after repeated password attempts.

These detections produce investigative alerts, not definitive proof of malicious activity.

## Sample Results

The included fictional dataset contains 11 authentication events. The initial analysis generated two alerts:

| Alert | Finding |
|---|---|
| Repeated Authentication Failures | Five failed logins associated with user `alex` and source IP `192.0.2.20` |
| Success After Repeated Failures | A subsequent successful login to the `email` resource |

The sample IP addresses are reserved for documentation and testing. The dataset does not represent actual users or an observed attack.

## Requirements

- Python 3.12 or a compatible Python 3 version
- pandas
- Git (optional, for version control)

## Setup and Usage

Clone the repository and enter the project directory:

```powershell
git clone https://github.com/MoAlhaddad/blueteam-soc-lab.git
cd blueteam-soc-lab
```

Create and activate a virtual environment on Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependency:

```powershell
python -m pip install pandas
```

Run the analysis:

```powershell
python .\src\analyze_logs.py
```

The script writes its findings to:

```text
reports/suspicious_events.csv
```

## Current Limitations

- Uses synthetic authentication data rather than live endpoint or SIEM telemetry.
- Implements simple threshold-based detections that require further validation.
- Does not establish whether an alert represents a confirmed compromise.
- Does not yet include automated tests, SIEM integration, or a full incident-response workflow.

## Planned Improvements

- Add automated tests for detection logic and edge cases.
- Improve alert deduplication and time-window handling.
- Add additional authentication detection scenarios.
- Develop Kusto Query Language (KQL) detection queries for Microsoft Sentinel.
- Write a simulated incident investigation report.
- Document investigation and false-positive analysis.

## Disclaimer

This project is intended for education and portfolio demonstration. All included authentication events are fictional. Alerts are illustrative and should not be used as a standalone production security control.