# Automated Linux Security Audit Tool

## Scenario

Following a two-week contractor engagement at **NexaCore Technologies**, the internal security team detected anomalous activity on a critical Linux server. Indicators included unrecognised user accounts, unauthorised services, and deviations from baseline configurations.

To validate system integrity before returning the server to production, a post-engagement security audit was initiated.

As the assigned Security Analyst, I developed an automated audit solution to systematically enumerate the system, identify potential security risks, and generate a structured report to support incident response and remediation efforts.

---

## Objective

Design and deploy a Bash-based security audit tool that:

* Automates enumeration across critical Linux security domains
* Identifies misconfigurations and potential privilege escalation vectors
* Reduces manual investigation time
* Produces a timestamped report for security review and incident documentation

---

## Script Overview

The audit script performs structured enumeration across eight key security domains using native Linux utilities. Output is streamed to both the terminal and a persistent report file using `tee`, ensuring real-time visibility and audit traceability.

| Command                | Purpose                                  |
| ---------------------- | ---------------------------------------- |
| `uname -a`, `hostname` | System identification and fingerprinting |
| `who`                  | Active session enumeration               |
| `/etc/passwd` parsing  | User account discovery                   |
| `/etc/group` analysis  | Privileged group identification          |
| `ss -tuln`             | Network port and exposure analysis       |
| `systemctl list-units` | Active service enumeration               |
| `find -perm -0002`     | World-writable file detection            |
| `find -perm -4000`     | SUID binary identification               |

The script appends all findings to a timestamped report file, enabling offline analysis and supporting incident documentation workflows.

---

## Audit Findings — NexaCore Server

| Finding                                                     | Risk Level | Why It Matters                                                                                                                      | Recommendation                                                             |
| ----------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 50+ user accounts detected                                  | Medium     | Large account footprint increases attack surface; dormant or orphaned accounts may be abused for persistence or unauthorised access | Perform account audit; disable or remove inactive users                    |
| Multiple sudo-enabled accounts (kali, Cybervault)           | Medium     | Increased likelihood of privilege escalation if credentials are compromised                                                         | Enforce least privilege; restrict sudo access to authorised personnel only |
| No exposed network ports                                    | Low        | No externally accessible services detected, reducing remote attack vectors                                                          | Maintain firewall rules and periodic port audits                           |
| 18 active services running                                  | Medium     | Each running service introduces potential vulnerabilities and persistence mechanisms                                                | Review necessity of services; disable non-essential processes              |
| No world-writable files detected                            | Low        | Reduces risk of unauthorised file modification or malicious script injection                                                        | Continue regular permission audits                                         |
| SUID binaries identified (kismet, fusermount3, ssh-keysign) | Medium     | SUID binaries can be exploited for local privilege escalation if vulnerable or misconfigured                                        | Validate against baseline; remove unnecessary SUID permissions             |

---

## Analyst Interpretation

### Privilege Escalation Risk

The presence of multiple sudo-enabled accounts introduces a significant escalation pathway. In the event of credential compromise, an attacker could gain full administrative control of the system.

### Attack Surface — Running Services

Eighteen active services were identified during the audit. Each service represents a potential entry point. Services such as `mysql`, `redis`, and `postgres` should be validated for necessity, secure configuration, and patch status.

### SUID Binary Abuse

SUID binaries execute with elevated privileges and are a well-known vector for local privilege escalation. Identified binaries should be reviewed against known vulnerabilities and restricted where possible.

### Post-Contractor Risk Consideration

Given recent third-party access, all accounts, services, and configurations introduced during the engagement should be reviewed to ensure compliance with internal security baselines and to eliminate potential persistence mechanisms.

---

## Skills Demonstrated

* Linux Security Auditing
* System Enumeration & Threat Surface Analysis
* Privilege Escalation Detection
* Network Exposure Assessment
* File Permission & SUID Analysis
* Bash Scripting & Automation
* Security Reporting & Documentation
* Incident Response Support

---

## How to Run

```bash
git clone https://github.com/Cybervault-1/My-cybersecurity-portfolio.git
cd My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool
chmod +x scripts/security_audit.sh
./scripts/security_audit.sh
```

The script outputs findings in real time and saves a timestamped report in the `reports/` directory.

---

## Future Improvements

* Export results in JSON format for SIEM ingestion (Microsoft Sentinel, Splunk)
* Implement alerting via email or webhook for high-risk findings
* Integrate CVE lookups for identified SUID binaries (NIST NVD)
* Automate execution using cron for continuous monitoring
* Extend coverage to include SSH hardening checks, failed login analysis, and firewall auditing

---

## Author

**Cybervault**
Cybersecurity Analyst
https://github.com/Cybervault-1
