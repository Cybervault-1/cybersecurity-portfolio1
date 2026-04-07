# Threat Intelligence

## Overview
Threat intelligence is the process of taking indicators of compromise 
found during an investigation and enriching them using external databases 
and tools. This helps confirm whether something is genuinely malicious, 
understand the wider context of an attack, and connect findings to known 
threat activity.

The two main tools used in this section are:

**VirusTotal** — checks domains, IPs, URLs and file hashes against over 
90 security vendors simultaneously and provides community-sourced 
intelligence about known threats.

**AbuseIPDB** — a community database where security teams around the world 
report malicious IP addresses. Searching an IP here shows how many times 
it has been reported, what type of attacks it was involved in, and when 
it was last seen.

---

## Why Threat Intelligence Matters
Finding a suspicious IP or domain in your logs is only the first step. 
Threat intelligence tools let you answer the bigger questions:

- Has anyone else seen this IP attacking their systems?
- Is this domain known to be associated with malware?
- What type of attack is this IP typically used for?
- Is this threat still active right now?

These answers turn a raw finding into a fully contextualised threat 
that can be properly escalated and remediated.

---

## Cases

### Case 01 — Domain Analysis
Investigation of the domain easyas123.tech identified during the 
Wireshark malware traffic analysis. The domain was submitted to 
VirusTotal for reputation checking and further context was gathered 
through the Details tab.

### Case 02 — IP Reputation Analysis
Demonstration of AbuseIPDB using a real recently reported malicious IP 
address. This case shows how to read and interpret an AbuseIPDB report 
including confidence scores, report counts, attack categories and 
recent activity.

### Case 03 — File Hash Investigation
Investigation of a file hash using VirusTotal including vendor 
detection results and sandbox behavior analysis.
