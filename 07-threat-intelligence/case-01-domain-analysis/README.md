# Case 01 — Domain Analysis: easyas123.tech

## Executive Summary
During the Wireshark malware traffic investigation a system was found 
repeatedly querying the domain easyas123.tech using LDAP-based Active 
Directory service discovery patterns. The domain was submitted to 
VirusTotal for reputation analysis. While 0 out of 94 vendors flagged 
it as malicious, further investigation revealed the domain is associated 
with a published malware traffic analysis exercise simulating a compromised 
Active Directory environment — confirming the suspicious behaviour observed 
in the network capture was consistent with real malware activity.

---

## Scenario
During Case 01 of the Wireshark investigation a host was found making 
repeated DNS queries to easyas123.tech using LDAP-based service discovery 
patterns normally associated with Windows Active Directory. The domain 
did not resolve successfully and the queries continued repeating — 
behaviour consistent with a compromised system trying to contact a 
command and control server.

As part of the investigation the domain was submitted to threat 
intelligence tools to determine its reputation and gather additional 
context.

## Objective
Use VirusTotal to check the reputation of easyas123.tech, interpret the 
results in the context of the wider investigation, and document findings 
professionally.

## Tools Used
- VirusTotal

## IOC Investigated
- Type: Domain
- Value: easyas123.tech
- Source: Wireshark Case 01 malware traffic analysis

---

## Investigation Steps

### Step 1 — Submit Domain to VirusTotal

The domain easyas123.tech was submitted to VirusTotal for reputation 
analysis against 94 security vendors.

**What VirusTotal does:**
VirusTotal checks the submitted indicator against over 90 security 
vendors simultaneously and returns a verdict from each one. A high 
number of detections confirms malicious activity. Zero detections does 
not automatically mean the indicator is safe — it means it has not been 
widely reported yet.

**Finding:**
0 out of 94 security vendors flagged easyas123.tech as malicious. The 
last analysis was performed approximately one month before this 
investigation.

The screenshot below shows the full detection results across all 94 
vendors with every vendor returning a clean verdict.

![VirusTotal detection results showing 0 out of 94 vendors flagging 
easyas123.tech as malicious](screenshots/01-easyas123-virustotal-detection.png)

---

### Step 2 — Investigate Further Using the Details Tab

A clean VirusTotal result does not end the investigation. The Details 
tab was checked for additional context including registration information, 
resolved IP addresses and any related files or URLs.

**Finding:**
The Details tab revealed a Google search result linking easyas123.tech 
to a published traffic analysis exercise from malware-traffic-analysis.net 
dated February 2026. The entry described:

- Domain: easyas123.tech
- AD environment name: EASYAS123
- Active Directory domain controller: 10.2.28.2
- LAN segment details matching the network seen in the PCAP file

This confirmed the domain was used to simulate a compromised Active 
Directory environment in a controlled malware traffic exercise — 
consistent with the LDAP-based DNS queries and beaconing behaviour 
observed during the Wireshark investigation.

The screenshot below shows the Google results section from the Details 
tab confirming the domain's association with the malware traffic exercise.

![VirusTotal details tab showing domain associated with malware traffic 
analysis exercise](screenshots/02-easyas123-virustotal-details.png)

---

## Findings Summary

| Field | Detail |
|-------|--------|
| IOC | easyas123.tech |
| IOC Type | Domain |
| VirusTotal Detections | 0 out of 94 |
| Last Analysis | 1 month ago |
| Context Found | Associated with malware traffic analysis exercise |
| AD Environment | EASYAS123 |
| Domain Controller IP | 10.2.28.2 |
| Behaviour Observed | LDAP-based beaconing with no successful resolution |
| Overall Assessment | Suspicious — consistent with simulated C2 activity |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| DNS | T1071.004 | The compromised system used DNS queries to attempt communication with an external domain using LDAP service discovery patterns |
| Application Layer Protocol | T1071 | LDAP protocol was abused to blend malicious traffic in with legitimate Active Directory communication |

---

## Conclusion
A clean VirusTotal result does not automatically clear a domain from 
suspicion. In this case 0 detections initially suggested the domain 
was safe but further investigation through the Details tab revealed 
important context that confirmed the suspicious behaviour observed 
in the network traffic.

The domain easyas123.tech was used to simulate a compromised Active 
Directory environment — exactly the kind of behaviour the Wireshark 
investigation identified. The repeated LDAP-based DNS queries with 
no successful resolution are consistent with malware attempting to 
contact a command and control server that is no longer active.

This case demonstrates an important lesson — threat intelligence tools 
provide one data point among many. Behavioural evidence from network 
traffic analysis carries equal weight and sometimes tells a clearer 
story than reputation scores alone.

## 🔑 Key Takeaways

- A clean VirusTotal result does not mean an indicator is safe. 
  Always investigate further using the Details tab and other sources
- Context from the original investigation is just as important as 
  external reputation scores
- LDAP-based DNS queries to non-corporate domains are a strong 
  indicator of compromise regardless of VirusTotal results
- Threat intelligence enrichment adds depth to an investigation 
  but should never replace analytical thinking
