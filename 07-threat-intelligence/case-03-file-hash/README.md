# Case 03 — File Hash Investigation: EICAR Test File

## Executive Summary
This case demonstrates the process of investigating a file hash using 
VirusTotal to identify whether a file is malicious. The EICAR test file 
hash was submitted to VirusTotal and returned detections from 67 out of 
94 security vendors. The Behavior tab revealed sandbox analysis results 
showing the file attempting to evade detection — demonstrating the complete 
file hash investigation workflow used in real SOC environments.

---

## Scenario
During the Splunk Case 02 investigation an attacker was found downloading 
a file called payload.exe from an external malicious server and executing 
it on the compromised workstation WKSTN-04. In a real investigation the 
analyst would extract the hash of that file and submit it to VirusTotal 
to identify what type of malware it is without needing to run it.

This case demonstrates that process using the EICAR test file — a 
well-known harmless file used by security professionals to test antivirus 
detection. While the file itself is not dangerous the investigation 
process is identical to analysing real malware.

## Objective
Use VirusTotal to investigate a file hash, interpret vendor detection 
results, analyse sandbox behavior data, map findings to MITRE ATT&CK, 
and document findings professionally.

## Tools Used
- VirusTotal

## IOC Investigated
- Type: File Hash (MD5)
- Value: 44d88612fea8a8f36de82e1278abb02f
- File Name: eicar.com
- File Size: 68 bytes
- Source: EICAR standard antivirus test file

---

## Background — What is a File Hash?
A file hash is a unique fingerprint generated from the contents of a 
file. Even changing a single character in a file completely changes its 
hash. This makes hashes extremely useful for:

- Identifying known malware without needing the actual file
- Confirming whether two files are identical
- Checking if a suspicious file matches known threat databases
- Sharing indicators of compromise between security teams

The most common hash types used in threat intelligence:

| Hash Type | Length | Example |
|-----------|--------|---------|
| MD5 | 32 characters | 44d88612fea8a8f36de82e1278abb02f |
| SHA1 | 40 characters | 3395856ce81f2b7382dee72602f798b642f14d8b |
| SHA256 | 64 characters | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f |

---

## Investigation Steps

### Step 1 — Submit Hash to VirusTotal

The MD5 hash of the file was submitted to VirusTotal for analysis 
against 94 security vendors.

**What to look for:**
The detection count is the first thing to check. A high number of 
vendor detections confirms the file is known malware. The threat 
categories and family labels tell you what type of malware it is. 
The community score shows how the wider security community rates 
the threat.

**Finding:**
67 out of 94 security vendors flagged the file as malicious. The 
results showed:

| Field | Detail |
|-------|--------|
| File Hash | 44d88612fea8a8f36de82e1278abb02f |
| Detections | 67 out of 94 vendors |
| Community Score | 3727 |
| File Size | 68 bytes |
| Last Analysis | 7 minutes before investigation |
| Threat Categories | Virus, Trojan |
| Family Labels | EICAR, test, file |
| Tags | powershell, known-distributor, attachment, via-tor |

The screenshot below shows the full detection results across all 94 
vendors with 67 returning malicious verdicts.

![VirusTotal detection results showing 67 out of 94 vendors flagging 
the file hash as malicious](screenshots/01-eicar-virustotal-detection.png)

---

### Step 2 — Review File Details

The Details tab was checked for additional information about the file 
including its properties, known names and any related files or URLs.

**What to look for:**
The Details tab shows the full file metadata including all hash types, 
file type, creation date and any names the file has been seen under. 
This helps confirm the file identity and find related threats.

**Finding:**
The Details tab confirmed the file properties and showed additional 
hash values for cross-referencing across different threat intelligence 
platforms. The file was identified as a standard EICAR test string 
distributed by Offensive Security for antivirus testing purposes.

The screenshot below shows the file details including hash values and 
file properties.

![VirusTotal details tab showing file properties and hash 
values](screenshots/02-eicar-virustotal-details.png)

---

### Step 3 — Analyse Sandbox Behavior

The Behavior tab was reviewed to understand what the file actually does 
when executed. Multiple sandboxes ran the file in isolated environments 
and recorded every action it performed.

**What to look for:**
The sandbox detections, behavior tags, dropped files and network 
communications sections all reveal what the file does when it runs. 
Evasion techniques are particularly important — files that detect 
sandbox environments and behave differently are more sophisticated 
threats that are harder to analyse.

**Finding:**
The Behavior tab revealed detailed sandbox analysis from 8 different 
environments:

**Sandbox Detections:**
| Sandbox | Verdict |
|---------|---------|
| Zenbox | MALWARE TROJAN |
| Lastline | MALWARE TROJAN |
| OS X Sandbox | MALWARE TROJAN EVADER |

The EVADER classification from OS X Sandbox is significant — it means 
the file detected it was being analysed and attempted to behave 
differently to avoid detection.

**Behavior Tags:**
| Tag | What it means |
|-----|--------------|
| checks-cpu-name | Checks what processor is running — used to detect virtual machines |
| detect-debug-environment | Checks if it is being analysed by a security tool |
| direct-cpu-clock-access | Accesses CPU clock directly to detect sandbox timing |
| long-sleep | Delays execution to wait for sandbox analysis to finish |
| sets-process-name | Renames itself to hide from process monitoring |

**Activity Summary:**
| Category | Count |
|----------|-------|
| MITRE Signatures | 6 Low, 46 High |
| Dropped Files | 9 total |
| Network Communications | 30 DNS, 24 IP, 2 URL |

The 46 high severity MITRE signature matches indicate the file 
performs a wide range of techniques associated with malware behaviour 
across multiple attack categories.

The screenshot below shows the full behavior analysis including sandbox 
detections, behavior tags and activity summary.

![VirusTotal behavior tab showing sandbox detections, evasion techniques 
and MITRE ATT&CK mappings](screenshots/03-eicar-virustotal-behavior.png)

---

## Findings Summary

| Field | Detail |
|-------|--------|
| IOC | 44d88612fea8a8f36de82e1278abb02f |
| IOC Type | File Hash MD5 |
| File Name | eicar.com |
| Vendor Detections | 67 out of 94 |
| Community Score | 3727 |
| Threat Categories | Virus, Trojan |
| Sandbox Verdicts | Malware Trojan, Malware Trojan Evader |
| Evasion Techniques | Sandbox detection, long sleep, CPU clock access |
| Network Activity | 30 DNS queries, 24 IP connections, 2 URLs |
| Overall Assessment | Confirmed malicious — high confidence |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Execution | T1059 | The file executed code when run in sandbox environments |
| Defense Evasion | T1497 | The file detected sandbox environments and attempted to evade analysis using CPU checks and long sleep delays |
| Discovery | T1082 | The file checked system information including CPU name and environment details |
| Command and Control | T1071 | Network communications were observed including DNS queries and IP connections during sandbox execution |
| Persistence | T1547 | Persistence mechanisms were detected during sandbox analysis |

---

## Conclusion
This investigation demonstrated the complete file hash analysis workflow 
using VirusTotal. The hash returned 67 detections from 94 vendors 
confirming the file as a known threat. The Behavior tab provided 
additional depth showing how the file behaves when executed — including 
sandbox evasion techniques that would make it harder to detect in a 
real environment.

The evasion techniques observed are particularly noteworthy. A file 
that checks whether it is being analysed and uses long sleep delays 
to wait for sandbox analysis to complete is designed specifically to 
avoid security tools. In a real investigation this level of 
sophistication would indicate a more advanced threat actor rather 
than opportunistic malware.

In a real SOC scenario if payload.exe from Case 02 had been found on 
the compromised system the analyst would extract its hash, submit it 
to VirusTotal, and use the detection results and behavior analysis to 
identify the malware family, understand its capabilities, and determine 
the full scope of the compromise.

## 🔑 Key Takeaways

- File hashes let you identify known malware without running the file — 
  always hash suspicious files before doing anything else with them
- A high detection count across many vendors is strong confirmation 
  of malicious activity
- The Behavior tab is more powerful than the Detection tab — it shows 
  what the file actually does not just whether vendors flag it
- Sandbox evasion techniques indicate a more sophisticated threat — 
  files that detect analysis environments require more careful handling
- Always check all three tabs on VirusTotal — Detection, Details and 
  Behavior together give the complete picture
- File hash analysis connects directly to incident response — knowing 
  what a file does helps you understand the full scope of a breach
