# Case 02 — IP Reputation Analysis: AbuseIPDB

## Executive Summary
This case demonstrates how to use AbuseIPDB to check the reputation of 
a suspicious IP address identified during a security investigation. A 
recently reported malicious IP was selected from the AbuseIPDB live feed 
and analysed in detail. The IP had been reported 32 times from 7 distinct 
sources for port scanning activity and was confirmed as actively engaged 
in abusive behaviour at the time of investigation.

---

## Scenario
During security investigations analysts frequently encounter IP addresses 
that appear suspicious based on their behaviour in logs. Before escalating 
a finding or blocking an IP it is important to check whether that IP has 
been reported by other organisations as malicious.

This case demonstrates the process of checking an IP address on AbuseIPDB 
to gather threat intelligence, interpret the results, and understand what 
the data means in the context of a real investigation.

## Objective
Use AbuseIPDB to investigate a reported malicious IP address, interpret 
the confidence score and report history, understand the attack categories, 
and document findings professionally.

## Tools Used
- AbuseIPDB

## IOC Investigated
- Type: IP Address
- Value: 66.185.112.249
- Source: AbuseIPDB recently reported IPs live feed

---

## Background — What is AbuseIPDB?
AbuseIPDB is a community-driven database where security teams and system 
administrators from around the world report IP addresses involved in 
malicious activity. When an IP attacks a system the analyst can report 
it here so that other organisations are warned.

Key fields to understand when reading an AbuseIPDB report:

| Field | What it means |
|-------|--------------|
| Abuse Confidence Score | Percentage likelihood the IP is malicious based on community reports. 0% means never reported, 100% means highly confirmed malicious |
| Total Reports | How many times the IP has been reported across all sources |
| Distinct Sources | How many different organisations reported it — more sources means more credibility |
| Last Reported | When the most recent report was filed — recent reports indicate active threats |
| Categories | What type of malicious activity the IP was involved in |
| ISP and Usage Type | Who owns the IP and what it is used for — data center IPs are more suspicious than home IPs |

---

## Investigation Steps

### Step 1 — Search the IP on AbuseIPDB

The IP address 66.185.112.249 was searched on AbuseIPDB to retrieve 
its full report history and reputation score.

**What to look for:**
The first things to check are the confidence score and total report 
count. A high confidence score with many reports from multiple distinct 
sources is strong confirmation of malicious activity. Even a low 
confidence score with many recent reports warrants attention.

**Finding:**
The IP was found in the AbuseIPDB database with the following details:

| Field | Detail |
|-------|--------|
| IP Address | 66.185.112.249 |
| Abuse Confidence Score | 5% |
| Total Reports | 32 |
| Distinct Sources | 7 |
| ISP | WoodyNet Inc |
| Usage Type | Data Center/Web Hosting |
| Country | United States |
| City | Dallas Texas |
| Last Reported | 4 minutes before investigation |

The screenshot below shows the full AbuseIPDB report for 66.185.112.249 
including the confidence score, report count and IP information.

![AbuseIPDB report showing 66.185.112.249 reported 32 times with port 
scanning activity confirmed as recently as 4 minutes before 
investigation](screenshots/03-abuseipdb-sample-ip.png)

---

### Step 2 — Interpret the Results

**The Confidence Score**
The confidence score of 5% is low but this does not mean the IP is safe. 
The score reflects how many vendors have confirmed it as malicious. Port 
scanning alone receives a lower confidence score than confirmed attacks 
because some legitimate security researchers also conduct port scans. 
The 32 reports and very recent activity are more meaningful indicators 
than the score alone.

**The Usage Type**
The IP is classified as Data Center/Web Hosting rather than a residential 
connection. This is significant because:
- Legitimate home users rarely conduct port scans
- Data center IPs are commonly used by attackers to launch automated 
  scanning campaigns
- A data center IP with multiple abuse reports is a strong indicator 
  of malicious infrastructure

**The Attack Category**
Every report in the history is categorised as Port Scan. Port scanning 
is typically the reconnaissance phase of an attack — the attacker is 
mapping out targets to find open ports and vulnerable services before 
attempting to exploit them.

**The Recent Activity**
The most recent report was filed just 4 minutes before this investigation. 
AbuseIPDB also displayed a warning stating the IP was potentially still 
actively engaged in abusive activities. This means the threat was live 
and ongoing at the time of investigation.

---

### Step 3 — Understand Port Scanning in Context

Port scanning is the first step most attackers take before launching 
an attack. It works like this:

The attacker sends connection requests to many different ports on a 
target system. The responses tell them which ports are open and what 
services are running. They then use this information to identify 
vulnerabilities they can exploit.

In a real SOC investigation if you saw 66.185.112.249 appearing in 
your firewall logs you would:

1. Check AbuseIPDB and find 32 reports of port scanning
2. Note the IP is from a data center — not a legitimate user
3. Note the most recent report was minutes ago — active threat
4. Recommend blocking the IP at the firewall immediately
5. Check whether any of your systems responded to the scan
6. Investigate whether any follow-up exploitation attempts occurred

---

## Findings Summary

| Field | Detail |
|-------|--------|
| IOC | 66.185.112.249 |
| IOC Type | IP Address |
| Abuse Confidence Score | 5% |
| Total Reports | 32 |
| Distinct Reporting Sources | 7 |
| Attack Category | Port Scanning |
| ISP | WoodyNet Inc |
| Usage Type | Data Center/Web Hosting |
| Location | Dallas Texas, United States |
| Last Reported | 4 minutes before investigation |
| Threat Status | Actively engaged in abusive activity |
| Overall Assessment | Suspicious — active port scanning from data center IP |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Active Scanning | T1595 | The IP was conducting repeated port scans against multiple targets — a classic pre-attack reconnaissance technique used to identify open services and potential vulnerabilities |
| Network Service Discovery | T1046 | Port scanning is used to discover what network services are running on target systems before attempting exploitation |

---

## Conclusion
This investigation demonstrated how AbuseIPDB provides rapid threat 
intelligence enrichment for suspicious IP addresses. The IP 66.185.112.249 
was confirmed as a malicious data center IP actively conducting port 
scanning operations against multiple targets at the time of investigation.

While the confidence score of 5% appears low, the combination of 32 
reports from 7 distinct sources, data center hosting classification, 
and activity confirmed just 4 minutes before the investigation all point 
to an active and ongoing threat. Confidence scores alone should never 
be the sole basis for a decision — the full context of the report 
history and IP information must be considered together.

In a real SOC environment this IP would be immediately blocked at the 
perimeter firewall and all internal systems would be checked for any 
signs of successful connection attempts from this source.

## 🔑 Key Takeaways

- A low confidence score does not mean an IP is safe — always read 
  the full report including total reports, distinct sources and 
  last reported date
- Data center IPs conducting port scans are almost always malicious — 
  legitimate users do not scan from hosting infrastructure
- Recent reports are more relevant than old ones — an IP reported 
  4 minutes ago is an active threat right now
- Port scanning is reconnaissance — if you see it in your logs check 
  immediately whether any follow-up exploitation attempts occurred
- AbuseIPDB is most powerful when combined with your own log analysis — 
  external reputation confirms what your internal evidence already suggests
