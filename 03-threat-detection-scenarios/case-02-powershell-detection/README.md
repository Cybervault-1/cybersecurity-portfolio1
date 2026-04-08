# Case 02 — Suspicious PowerShell Detection Rule

## Overview
This detection rule identifies malicious PowerShell activity by monitoring 
for encoded commands executed via cmd.exe. This combination is rarely 
seen in legitimate administrator activity and is a strong indicator of 
an attacker using PowerShell to hide malicious commands from security 
tools.

---

## Scenario
The SecureCore Ltd SOC team wants to ensure that any future PowerShell 
based attack is caught automatically the moment encoded commands start 
running. The detection must fire early enough to allow the analyst to 
investigate and isolate the affected machine before malware is deployed.

---

## Detection Logic

A malicious PowerShell attack shows these characteristics:
- PowerShell launched from cmd.exe rather than directly
- Commands are encoded in Base64 to hide their purpose
- Multiple encoded commands running in quick succession
- Activity concentrated on one specific machine

The rule triggers when encoded PowerShell commands are detected running 
via cmd.exe on any machine in the environment.

---

## SPL Detection Query

```
index=main source="powershell-logs.csv" encoded=true
| stats count by user, extracted_host, parent_process
| where parent_process="cmd.exe"
| table user, extracted_host, parent_process, count
| rename count as "Encoded Commands Detected"
```

## Query Breakdown

| Line | What it does |
|------|-------------|
| `encoded=true` | Filter only commands that were deliberately obfuscated |
| `stats count by user, extracted_host, parent_process` | Count encoded commands per user per machine per parent process |
| `where parent_process="cmd.exe"` | Only return results where PowerShell was launched from cmd.exe |
| `table` | Display as a clean readable table |
| `rename` | Make the count column more descriptive |

---

## Test Results

The query was run against the PowerShell investigation log file. 
The screenshot below shows the detection firing and identifying 
the exact machine and user responsible.

![PowerShell detection rule firing showing admin on WKSTN-04 
executed 3 encoded commands via 
cmd.exe](screenshots/02-powershell-detection-rule.png)

The rule detected 3 encoded commands run by the admin account on 
WKSTN-04 via cmd.exe. In a real environment this alert firing at 
09:20 would have given the analyst time to isolate WKSTN-04 before 
the malware was downloaded at 09:27 and executed at 09:30.

---

## Alert Configuration

In a production Splunk environment this query would be saved as a 
scheduled alert running every 5 minutes. When results are returned 
Splunk would:

- Send an immediate high priority notification to the on-duty analyst
- Create a critical severity ticket in the incident management system
- Log the alert for audit purposes

This alert should be configured as high priority because encoded 
PowerShell via cmd.exe almost always indicates malicious activity 
with very few legitimate exceptions.

---

## Response Actions When Alert Fires

1. Identify the affected machine and user from the alert
2. Isolate the machine from the network immediately
3. Check PowerShell logs for the full list of commands run
4. Decode any encoded commands to understand what they did
5. Check for new local accounts created during the attack window
6. Check C:\Windows\Temp for any downloaded executables
7. Begin full forensic investigation of the affected machine
8. Document findings and actions taken

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| PowerShell | T1059.001 |
| Obfuscated Files or Information | T1027 |
| Command and Scripting Interpreter | T1059.003 |
