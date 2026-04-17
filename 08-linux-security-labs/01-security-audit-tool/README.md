# Automated Security Audit Tool

## Scenario

You've just joined **NexaCore Technologies** as a Security Analyst. On your first day, your manager pulls you aside.

> *"We had a contractor working on this Linux server for the past two weeks. He's gone now, but before he left, one of our engineers noticed some strange behaviour — unfamiliar user accounts, unusual open ports, and services running that nobody recognises. We don't have time to check it manually. I need you to build a script that automatically audits this server and gives us a full security report."*

Your job: build an automated script that scans the server for security risks and produces a structured report for the security team.

## Objective

Develop a bash script that systematically audits a Linux system across 8 security categories and automatically generates a timestamped report.

## Script Overview

The audit script performs sequential enumeration across eight security categories using native Linux tools. Each section writes output simultaneously to the terminal and to a timestamped report file using the `tee` command, ensuring a complete audit trail.

| Command | Purpose |
|---|---|
| `uname -a` / `hostname` | System fingerprinting |
| `who` | Active session detection |
| `cat /etc/passwd` / `cut` | Full user account enumeration |
| `grep` against `/etc/group` | Privilege escalation surface mapping |
| `ss -tuln` | Exposed network port detection |
| `systemctl list-units` | Running service enumeration |
| `find` with `-perm -0002` | World-writable file detection |
| `find` with `-perm -4000` | SUID binary identification |

## Step 1 — Setting Up the Project

The project folder structure was created to organise scripts, reports, and screenshots.

```bash
mkdir -p ~/My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool/scripts
mkdir -p ~/My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool/reports
mkdir -p ~/My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool/screenshots
```

## Step 2 — Making the Script Executable

After writing the audit script, execute permissions were granted before running it.

```bash
chmod +x scripts/security_audit.sh
ls -l scripts/security_audit.sh
```

## Step 3 — Running the Audit

The script was executed against the NexaCore server to perform a full security audit across all 8 categories.

```bash
./scripts/security_audit.sh
```

![Script Execution Top](screenshots/01-script-top.png)

![Script Execution Bottom](screenshots/02-script-bottom.png)

## Audit Findings — NexaCore Server

| Finding | Risk Level | Why It Matters | Recommendation |
|---|---|---|---|
| 50+ user accounts detected | Medium | Large attack surface; legacy or orphaned accounts may be leveraged for unauthorised access | Conduct user access review; disable or remove inactive accounts |
| kali and Cybervault hold sudo privileges | Medium | Multiple sudo-enabled accounts increase privilege escalation risk | Apply principle of least privilege; restrict sudo to authorised administrators only |
| No exposed network ports | Low | Reduces external attack surface; no immediate network-based threat vector identified | Maintain current firewall and port management policy |
| 18 active services running | Medium | Unnecessary services increase attack surface and persistence opportunities | Audit each service; disable non-essential services |
| No world-writable files detected | Low | Eliminates a common vector for unauthorised file modification or script injection | Maintain regular permission audits |
| SUID binaries identified — kismet, fusermount3, ssh-keysign | Medium | SUID binaries can be abused for local privilege escalation if misconfigured or vulnerable | Review SUID binaries against approved baseline; remove unnecessary SUID flags |

## Analyst Interpretation

**Privilege Escalation Risk**
Two accounts holding sudo privileges on a server recently accessed by an external contractor represents an elevated risk. Any account compromise — particularly through credential theft or brute force — could result in full root-level access and complete system compromise.

**Attack Surface — Running Services**
Eighteen active services were identified at the time of audit. Each running service represents a potential entry point. Services such as `mysql`, `redis`, and `postgres` detected during enumeration should be reviewed to confirm they are required, patched, and not externally accessible.

**SUID Binary Abuse**
SUID files execute with the privileges of the file owner rather than the user running them. Tools such as `kismet` holding SUID flags present a potential local privilege escalation vector, particularly if the binary contains known vulnerabilities or is accessible to low-privileged users.

**Contractor Access Review**
Given the context of this audit — a post-contractor system review — particular attention should be paid to any accounts, services, or scheduled tasks created during the engagement period that fall outside approved configurations.

## Skills Demonstrated

- Linux Security Auditing
- System Enumeration and Reconnaissance
- Privilege Escalation Detection
- Network Exposure Analysis
- File Permission Auditing
- SUID Binary Analysis
- Bash Scripting and Automation
- Security Audit Reporting and Documentation
- Incident Response Support

## How to Run

```bash
git clone https://github.com/Cybervault-1/My-cybersecurity-portfolio.git
cd My-cybersecurity-portfolio/08-linux-security-labs/01-security-audit-tool
chmod +x scripts/security_audit.sh
./scripts/security_audit.sh
```

The script prints all findings to the terminal in real time and saves a complete timestamped report to the `reports/` directory upon completion.

## Future Improvements

- Integrate JSON output format for ingestion into SIEM platforms such as Microsoft Sentinel or Splunk
- Implement automated alerting via email or Slack webhook when high-risk findings are detected
- Add CVE cross-referencing for identified SUID binaries against the NIST NVD database
- Schedule automated weekly audits using cron for continuous monitoring
- Extend scope to include failed login attempts, SSH configuration review, and firewall rule analysis

## Author

**Adedeji Adetayo**
Cybersecurity Analyst
[GitHub](https://github.com/Cybervault-1)
