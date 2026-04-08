# Case 02 — Unauthorized Program Execution on WKSTN-09

## Executive Summary
A malware infection was detected on workstation WKSTN-09 at SecureCore 
Ltd after user tbrady opened a malicious email attachment disguised as 
an invoice. The executable file invoice_april.exe launched directly from 
the Downloads folder, connected to a command and control server, dropped 
a second malware file, created registry persistence, conducted system 
reconnaissance and attempted lateral movement to both the domain 
controller and file server. The full attack chain was reconstructed 
using Sysmon process creation, network connection and registry 
modification logs.

---

## Scenario
The SOC team receives a Sysmon alert showing that an unauthorised 
program was executed on workstation WKSTN-09 by user tbrady. The 
program was not installed through any official IT process and was not 
approved by the organisation. As the analyst on duty the task is to 
investigate what was executed, how it got onto the machine and what 
damage it caused.

## Objective
Use Sysmon logs in Splunk to investigate unauthorised program execution, 
trace the complete attack chain from email attachment to lateral movement, 
identify all malicious indicators and document findings professionally.

## Tools Used
- Splunk Enterprise
- SPL (Search Processing Language)
- Sysmon event logs

## Dataset
- File: unauthorized-execution-logs.csv
- Index: main
- Total Events: 16
- Log Fields: time, host, user, EventCode, process_name, process_path,
  parent_process, parent_path, command_line, destination_ip,
  destination_port, file_created, registry_key, description

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs

The dataset was loaded into Splunk and raw logs were reviewed to 
understand the full scope of activity on WKSTN-09.

**Query used:**
```
index=main source="unauthorized-execution-logs.csv"
```

**Finding:**
16 total Sysmon events were present covering activity from 13:00 to 
13:20 on WKSTN-09 for user tbrady. Initial review immediately revealed 
two processes running from suspicious user-writable locations and a 
clear pattern of malicious behaviour starting at 13:15.

The screenshot below shows the full raw dataset as it appeared in Splunk.

![Raw Sysmon logs showing 16 events across the investigation 
window](screenshots/01-raw-sysmon-logs.png)

---

### Step 2 — Identify Suspicious Process Locations

The process_path field was reviewed to identify any processes running 
from unusual or suspicious locations.

**Finding:**
5 unique process paths were identified. Three were legitimate:

- C:\Windows\System32\cmd.exe
- C:\Program Files\Microsoft Office\outlook.exe
- C:\Windows\explorer.exe

Two were highly suspicious:

| Process | Path | Why suspicious |
|---------|------|---------------|
| invoice_april.exe | C:\Users\tbrady\Downloads\ | Executable files should never run directly from Downloads |
| winupdate.exe | C:\Users\tbrady\AppData\Roaming\ | Legitimate Windows processes never run from AppData\Roaming |

The name winupdate.exe is deliberately chosen to look like a legitimate 
Windows update process. This masquerading technique is designed to 
make the malware blend in with normal system activity.

The screenshot below shows the process_path field breakdown confirming 
the two suspicious locations.

![Process path analysis showing invoice_april.exe and winupdate.exe 
running from suspicious user-writable 
locations](screenshots/02-suspicious-process-paths.png)

---

### Step 3 — Reconstruct the Full Attack Chain

All 16 Sysmon events were retrieved in chronological order to reconstruct 
the complete attack from the initial email attachment through to lateral 
movement across two internal servers.

**Query used:**
```
index=main source="unauthorized-execution-logs.csv"
| table time, user, process_name, parent_process, command_line, 
  destination_ip, description
| sort time
```

**Finding:**
The full attack chain was reconstructed across six stages:

**Stage 1 — Normal Activity (13:00 to 13:10)**
tbrady logged in normally, opened Outlook and connected to Microsoft 
servers via HTTPS. All activity appeared completely legitimate.

**Stage 2 — Initial Infection (13:15 to 13:16:00)**
Outlook downloaded invoice_april.exe as an email attachment and tbrady 
executed it directly from the Downloads folder. Outlook spawning an 
executable process is a critical red flag. A real invoice would be a 
PDF or Word document — never an executable file.

**Stage 3 — C2 Communication and Malware Deployment (13:16:10 to 13:16:40)**
invoice_april.exe immediately connected to the C2 server at 91.108.4.200 
on port 8080. It then dropped a second malware file called winupdate.exe 
into AppData\Roaming and launched it. winupdate.exe also connected to 
the same C2 server confirming a persistent backdoor was established.

**Stage 4 — Persistence (13:16:50)**
winupdate.exe created a registry run key to ensure it would automatically 
restart every time the machine rebooted — meaning simply shutting down 
the machine would not remove the malware.

**Stage 5 — Reconnaissance (13:17)**
winupdate.exe launched four cmd.exe commands in quick succession:
- `whoami` — identified the user account the malware was running as
- `systeminfo` — gathered detailed information about the machine
- `net user` — listed all user accounts on the system
- `tasklist` — enumerated all running processes

**Stage 6 — Lateral Movement (13:18 to 13:20)**
winupdate.exe attempted to connect to two internal servers via SMB 
on port 445 — the domain controller at 10.0.0.5 and the file server 
at 10.0.0.20.

The screenshot below shows the complete attack chain from normal 
activity through to lateral movement.

![Full attack chain showing complete progression from email attachment 
execution through C2 communication reconnaissance and lateral 
movement](screenshots/03-full-attack-chain.png)

---

### Step 4 — Confirm Lateral Movement Evidence

The lateral movement attempts were isolated to confirm the scope of 
the network threat.

**Query used:**
```
index=main source="unauthorized-execution-logs.csv" 
destination_ip IN ("10.0.0.5", "10.0.0.20")
| table time, process_name, process_path, destination_ip, 
  destination_port, description
| sort time
```

**Finding:**
Two lateral movement attempts were confirmed within 2 minutes of each 
other:

| Time | Target | Port | Server Role |
|------|--------|------|-------------|
| 13:18:00 | 10.0.0.5 | 445 | Domain Controller |
| 13:20:00 | 10.0.0.20 | 445 | File Server |

Both connections used port 445 which is the SMB protocol. SMB is 
commonly exploited for lateral movement because it allows file sharing 
and remote execution across Windows networks. Access to the domain 
controller would give the attacker control over every account and 
machine in the organisation.

The screenshot below shows both lateral movement attempts confirmed.

![Lateral movement evidence showing winupdate.exe connecting to domain 
controller and file server on port 445](screenshots/04-lateral-movement.png)

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Compromised machine | WKSTN-09 |
| Affected user | tbrady |
| Initial infection vector | Malicious email attachment — invoice_april.exe |
| Parent process of malware | outlook.exe |
| Malware files | invoice_april.exe in Downloads, winupdate.exe in AppData\Roaming |
| C2 server | 91.108.4.200 on port 8080 |
| Persistence mechanism | Registry run key created by winupdate.exe |
| Reconnaissance commands | whoami, systeminfo, net user, tasklist |
| Lateral movement targets | 10.0.0.5 domain controller, 10.0.0.20 file server |
| Attack duration | 20 minutes from infection to lateral movement |
| Severity | Critical |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Spearphishing Attachment | T1566.001 | Malware was delivered as an email attachment disguised as an invoice |
| User Execution | T1204.002 | tbrady manually opened and executed the malicious attachment |
| Masquerading | T1036 | winupdate.exe was named to look like a legitimate Windows update process |
| Command and Control | T1071 | Both malware files connected to 91.108.4.200 on port 8080 for C2 |
| Registry Run Keys | T1547.001 | A registry run key was created to ensure winupdate.exe launches after reboot |
| System Information Discovery | T1082 | whoami and systeminfo were used to gather information about the system |
| Account Discovery | T1087 | net user was used to enumerate all accounts on the machine |
| Process Discovery | T1057 | tasklist was used to enumerate all running processes |
| Lateral Movement via SMB | T1021.002 | Connections to domain controller and file server on port 445 |

---

## Conclusion
This investigation confirmed a successful malware infection on WKSTN-09 
originating from a malicious email attachment. The attacker disguised 
malware as an invoice knowing that finance-related files are commonly 
opened without suspicion. Once tbrady executed the file the attack 
progressed rapidly through C2 communication, persistence creation, 
reconnaissance and lateral movement in under 20 minutes.

The attack exploited two human factors. First tbrady opened an executable 
file from an email without questioning why an invoice would be an .exe 
file. Second there were no technical controls in place to prevent 
executable files from running directly from email client downloads.

The lateral movement to both the domain controller and file server means 
this incident must be treated as a potential full network compromise. 
The attacker had access to the most critical systems in the organisation 
and may have exfiltrated data or created additional persistence mechanisms 
that have not yet been discovered.

## 🔑 Key Takeaways

- Executable files in emails are almost always malicious. Real invoices 
  and documents are PDFs or Office files not .exe files.
- Email clients should never be able to directly launch executable 
  attachments. Technical controls must prevent this.
- Masquerading process names is a common evasion technique. Always 
  verify the full path of any suspicious process not just its name.
- Reconnaissance commands immediately after malware execution confirm 
  the attacker is actively controlling the machine in real time.
- Two lateral movement targets in 2 minutes shows how fast an attacker 
  can spread once inside. Speed of detection and response is critical.

---

## Recommended Actions
- Isolate WKSTN-09 from the network immediately
- Delete invoice_april.exe from C:\Users\tbrady\Downloads
- Delete winupdate.exe from C:\Users\tbrady\AppData\Roaming
- Remove the registry run key created by winupdate.exe
- Block 91.108.4.200 at the perimeter firewall
- Check domain controller 10.0.0.5 and file server 10.0.0.20 logs 
  for any successful connections from WKSTN-09
- Scan all other machines for invoice_april.exe and winupdate.exe
- Rebuild WKSTN-09 from a clean image after forensic investigation
- Implement email attachment scanning to block executable files
- Configure email gateway to block .exe attachments entirely
- Conduct security awareness training focused on email attachment safety
