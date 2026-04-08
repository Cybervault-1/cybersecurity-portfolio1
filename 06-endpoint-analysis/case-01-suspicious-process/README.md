# Case 01 — Suspicious Process Detection on WKSTN-07

## Executive Summary
A malware infection was detected on workstation WKSTN-07 at SecureCore 
Ltd. Sysmon logs revealed that a malicious file called update.exe was 
created by Chrome after the user likely clicked a malicious link. The 
malware connected to an external command and control server, dropped a 
second malicious file disguised as a legitimate Windows process, created 
a registry persistence mechanism, conducted reconnaissance across the 
system and attempted lateral movement to the domain controller. The 
attack was fully mapped using Sysmon process creation, network connection 
and registry modification events.

---

## Scenario
A SOC alert fires at SecureCore Ltd showing unusual process activity on 
workstation WKSTN-07. Sysmon logs show a process called update.exe 
started running from an unusual location and immediately made a network 
connection to an external IP. It then created a new file and launched 
another process. As the SOC analyst on duty the task is to investigate 
what happened on this machine, trace the full attack chain and determine 
the scope of the compromise.

## Objective
Use Sysmon logs in Splunk to investigate suspicious process activity, 
trace the complete attack chain from initial infection to lateral 
movement, identify all malicious indicators and document findings 
professionally.

## Tools Used
- Splunk Enterprise
- SPL (Search Processing Language)
- Sysmon event logs

## Dataset
- File: sysmon-logs.csv
- Index: main
- Total Events: 15
- Log Fields: time, host, user, EventCode, process_name, process_path,
  parent_process, parent_path, command_line, destination_ip,
  destination_port, file_created, registry_key, description

---

## Background — What is Sysmon?

Sysmon stands for System Monitor. It is a free Windows tool from 
Microsoft that records detailed information about everything happening 
on a machine. Unlike standard Windows event logs which only record 
basic authentication events, Sysmon records:

| Event Code | What it records |
|------------|----------------|
| 1 | Process creation — every program that starts running |
| 3 | Network connection — every connection a program makes |
| 11 | File creation — every file written to disk |
| 13 | Registry value set — changes to Windows registry keys |

In a real SOC Sysmon is installed on every Windows machine and its 
logs are forwarded to Splunk giving analysts deep visibility into 
exactly what is happening at the system level.

---

## Investigation Steps

### Step 1 — Load and Review Raw Logs

The dataset was loaded into Splunk and raw logs were reviewed to 
understand the full scope of activity on WKSTN-07.

**Query used:**
```
index=main source="sysmon-logs.csv"
```

**Finding:**
15 total Sysmon events were present. The logs covered activity from 
08:00 to 08:20 on WKSTN-07 for user jsmith. Initial review of the 
process_path field immediately revealed two processes running from 
highly suspicious locations — one from AppData\Roaming and one from 
C:\Windows\Temp.

The screenshot below shows the full raw dataset as it appeared in Splunk.

![Raw Sysmon logs showing 15 events across the investigation 
window](screenshots/01-raw-sysmon-logs.png)

---

### Step 2 — Identify Suspicious Process Locations

The process_path field was reviewed to identify any processes running 
from unusual or suspicious locations.

**Finding:**
6 unique process paths were identified. Four were legitimate:

- C:\Windows\System32\cmd.exe
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- C:\Program Files\Google\Chrome\chrome.exe
- C:\Windows\explorer.exe

Two were highly suspicious:

| Process | Path | Why suspicious |
|---------|------|---------------|
| update.exe | C:\Users\jsmith\AppData\Roaming\ | Legitimate software never runs from AppData\Roaming |
| svchost32.exe | C:\Windows\Temp\ | Real svchost.exe runs from System32 never from Temp |

The svchost32.exe name is also suspicious. The real Windows process 
is called svchost.exe not svchost32.exe. The attacker deliberately 
named their malware to look like a legitimate Windows process — a 
technique called masquerading.

The screenshot below shows the process_path field breakdown confirming 
the two suspicious locations.

![Process path analysis showing update.exe and svchost32.exe running 
from suspicious locations](screenshots/02-suspicious-process-paths.png)

---

### Step 3 — Investigate the Suspicious Processes

Both suspicious processes were isolated and their full behaviour 
was examined including parent processes, network connections and 
descriptions.

**Query used:**
```
index=main source="sysmon-logs.csv" 
(process_name="update.exe" OR process_name="svchost32.exe")
| table time, process_name, process_path, parent_process, 
  destination_ip, description
| sort time
```

**Finding:**
The results revealed a clear attack progression:

| Time | Event |
|------|-------|
| 08:15:00 | update.exe created by chrome.exe — browser spawned malware |
| 08:15:10 | update.exe connects to 185.220.101.45 — first C2 contact |
| 08:15:20 | update.exe drops svchost32.exe in C:\Windows\Temp |
| 08:15:30 | svchost32.exe launches — malicious child process running |
| 08:15:40 | svchost32.exe connects to 185.220.101.45 — C2 confirmed |
| 08:15:50 | svchost32.exe modifies registry — persistence created |
| 08:17:00 | svchost32.exe connects to 10.0.0.5 — lateral movement attempt |

Chrome spawning an executable process is a critical red flag. 
Browsers should never create executable files directly. This 
indicates jsmith either clicked a malicious link or visited a 
compromised website that automatically downloaded and executed 
the malware.

The screenshot below shows the suspicious process investigation 
results.

![Suspicious process investigation showing full behaviour of 
update.exe and svchost32.exe including C2 connections and lateral 
movement](screenshots/03-suspicious-processes.png)

---

### Step 4 — Reconstruct the Full Attack Chain

All 15 Sysmon events were retrieved in chronological order to 
reconstruct the complete attack from initial infection to final 
stage.

**Query used:**
```
index=main source="sysmon-logs.csv"
| table time, process_name, parent_process, command_line, 
  destination_ip, description
| sort time
```

**Finding:**
The full attack chain was reconstructed:

**Stage 1 — Normal Activity (08:00 to 08:10)**
jsmith logged in normally, opened Chrome and browsed the web with 
normal HTTPS connections to Google.

**Stage 2 — Initial Infection (08:15)**
Chrome spawned update.exe from AppData\Roaming — the user likely 
clicked a malicious link or a drive-by download occurred. Within 
10 seconds update.exe connected to the C2 server at 185.220.101.45 
on port 4444.

**Stage 3 — Malware Deployment (08:15:20 to 08:15:50)**
update.exe dropped svchost32.exe into C:\Windows\Temp and launched 
it. svchost32.exe immediately connected to the same C2 server and 
created a registry run key to ensure it survives system reboots.

**Stage 4 — Reconnaissance (08:16)**
svchost32.exe launched four cmd.exe commands in quick succession:
- `whoami` — checked what user account the malware was running as
- `ipconfig` — mapped the network configuration
- `net user` — listed all user accounts on the machine
- `net localgroup administrators` — identified admin accounts

**Stage 5 — Lateral Movement (08:17)**
svchost32.exe attempted to connect to the domain controller at 
10.0.0.5 on port 445 — the SMB protocol used for Windows file 
sharing and commonly exploited for lateral movement.

**Stage 6 — Further Attack (08:20)**
svchost32.exe launched PowerShell with an encoded command — 
the same technique seen in the PowerShell investigation. This 
suggests the attacker was preparing for further exploitation.

The screenshot below shows the complete attack chain from normal 
activity through to the final encoded PowerShell execution.

![Full attack chain showing complete progression from browser 
infection through C2 communication reconnaissance and lateral 
movement attempt](screenshots/04-full-attack-chain.png)

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Compromised machine | WKSTN-07 |
| Affected user | jsmith |
| Initial infection vector | Chrome spawned update.exe — likely malicious download |
| Malware files | update.exe in AppData\Roaming, svchost32.exe in C:\Windows\Temp |
| C2 server | 185.220.101.45 on port 4444 |
| Persistence mechanism | Registry run key created by svchost32.exe |
| Reconnaissance commands | whoami, ipconfig, net user, net localgroup administrators |
| Lateral movement attempt | Connection to domain controller 10.0.0.5 on port 445 |
| Final stage | Encoded PowerShell launched for further attack |
| Severity | Critical |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Drive-by Compromise | T1189 | Malware was likely downloaded through the browser when jsmith visited a malicious website |
| Masquerading | T1036 | svchost32.exe was named to look like the legitimate Windows svchost.exe process |
| Command and Control | T1071 | Both malware files connected to 185.220.101.45 on port 4444 for C2 communication |
| Registry Run Keys | T1547.001 | A registry run key was created to ensure svchost32.exe launches automatically after reboot |
| System Information Discovery | T1082 | whoami and ipconfig were used to gather information about the compromised system |
| Account Discovery | T1087 | net user and net localgroup administrators were used to enumerate accounts |
| Lateral Movement via SMB | T1021.002 | Connection to domain controller on port 445 indicates an SMB lateral movement attempt |
| PowerShell | T1059.001 | Encoded PowerShell was launched as the final stage of the attack |

---

## Conclusion
This investigation confirmed a full malware infection on WKSTN-07 
starting from what was likely a malicious browser download. The 
attacker deployed two malware files, established command and control 
communication, created persistence to survive reboots, conducted 
system reconnaissance and attempted to move laterally to the domain 
controller — all within 5 minutes of the initial infection.

The use of a masqueraded process name and suspicious file locations 
shows the attacker understood basic detection evasion. The speed of 
the attack from infection to lateral movement attempt in under 2 
minutes highlights how quickly a single endpoint compromise can 
escalate into a network-wide threat.

The encoded PowerShell launched at 08:20 suggests the attacker was 
preparing for a second stage payload. Catching this investigation 
at this point prevented what could have been a significantly larger 
breach.

## 🔑 Key Takeaways

- Process paths matter as much as process names. Legitimate Windows 
  processes always run from expected locations like System32 or 
  Program Files. Anything running from Temp or AppData is suspicious.
- Browsers should never spawn executable processes. Any time this 
  happens it must be investigated immediately.
- Masquerading is common. Attackers name their malware after real 
  Windows processes hoping analysts will not notice the difference. 
  Always verify the full path not just the name.
- Reconnaissance commands after malware execution mean the attacker 
  is planning to go further. Early detection at this stage prevents 
  lateral movement.
- Registry persistence means simply removing the malware file is not 
  enough. The registry key must also be found and removed or the 
  malware will restart after reboot.

---

## Recommended Actions
- Isolate WKSTN-07 from the network immediately
- Delete update.exe from C:\Users\jsmith\AppData\Roaming
- Delete svchost32.exe from C:\Windows\Temp
- Remove the registry run key created by svchost32.exe
- Block 185.220.101.45 at the perimeter firewall
- Check domain controller 10.0.0.5 logs for any successful 
  connections from WKSTN-07
- Scan all other machines for update.exe and svchost32.exe
- Rebuild WKSTN-07 from a clean image after forensic investigation
- Review jsmith's browsing history to identify the malicious website
- Enable web filtering to block drive-by download sites
