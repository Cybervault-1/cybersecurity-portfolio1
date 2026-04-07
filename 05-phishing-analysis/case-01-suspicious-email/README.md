# Case 01 — Suspicious Email Investigation

## Executive Summary
A phishing email impersonating Microsoft was reported by an employee at 
SecureCore Ltd. The email used typosquatting, urgency tactics and a 
credential harvesting link to trick the victim into surrendering their 
Microsoft account credentials. Investigation confirmed the email was sent 
through a known malicious Tor exit node with a 100% abuse confidence score 
and over 6,500 reports from 595 organisations worldwide. The phishing link 
pointed to a Russian domain designed to harvest credentials. This was a 
deliberate and sophisticated credential theft attempt.

---

## Scenario
It is Tuesday morning at SecureCore Ltd. An employee named Sarah forwards 
a suspicious email to the security team with the subject line "Your Microsoft 
Account Has Been Suspended." She is concerned because the email looks 
convincing and is threatening to permanently delete her account if she does 
not act within 24 hours. As the SOC analyst on duty the task is to investigate 
whether this is a legitimate Microsoft email or a phishing attempt.

## Objective
Analyse the suspicious email to determine whether it is a phishing attempt, 
identify all malicious indicators, trace the sending infrastructure, check 
the reputation of identified IOCs, and document findings professionally.

## Tools Used
- AbuseIPDB
- VirusTotal
- Manual email header analysis

## Email Sample
The full email sample is available in the repository:
[phishing-email.txt](phishing-email.txt)

---

## Background — How Phishing Works
Phishing is one of the most common attack vectors in cybersecurity. 
Attackers send fake emails impersonating trusted organisations to trick 
victims into:

- Clicking malicious links that lead to credential harvesting pages
- Downloading malicious attachments containing malware
- Providing sensitive information directly in reply

The most effective phishing emails create a sense of urgency that pushes 
the victim to act before thinking carefully. Phrases like "your account 
will be deleted", "verify within 24 hours" and "unusual activity detected" 
are classic social engineering techniques designed to bypass rational 
thinking through fear and panic.

---

## Investigation Steps

### Step 1 — Initial Email Review

The email was read carefully before running any tools. This first pass 
focuses on identifying obvious red flags visible to the naked eye.

**What to look for:**
Sender address legitimacy, domain spelling, urgency language, threatening 
consequences, suspicious links and mismatched branding.

**Finding:**
Three immediate red flags were identified:

**Red Flag 1 — Typosquatted Sender Domain**
The email came from:
```
security@micros0ft-support.com
```
The letter O in Microsoft has been replaced with a zero. This technique 
is called typosquatting — registering a domain that looks almost identical 
to a legitimate one. The real Microsoft domain is microsoft.com. This 
domain has nothing to do with Microsoft.

**Red Flag 2 — Malicious Link**
The email contained a link to:
```
http://micros0ft-account-verify.ru/login?user=sarah.jones@securecore.com
```
Three problems with this link. The domain again uses zero instead of O. 
The domain ends in .ru which is the Russian country code — Microsoft 
would never send account verification links to a Russian domain. The URL 
also contains the victim's email address as a parameter confirming this 
was a targeted attack against Sarah specifically.

**Red Flag 3 — Urgency and Fear Tactics**
The email used three psychological pressure techniques:
- "Your account has been temporarily suspended"
- "Verify your identity within 24 hours"
- "Your account will be permanently deleted"

These threats are designed to panic the victim into clicking without 
thinking. This is social engineering — manipulating human psychology 
rather than exploiting technical vulnerabilities.

The screenshot below shows the full phishing email content with all 
red flags visible.

![Full phishing email showing typosquatted sender domain, malicious 
link and urgency tactics](screenshots/03-phishing-email-content.png)

---

### Step 2 — Email Header Analysis

Beyond the visible content every email contains hidden technical headers 
that reveal where it actually came from and how it was sent. These headers 
were analysed to trace the sending infrastructure.

**What to look for:**
The originating IP address, the mail server used, the X-Mailer field 
and any authentication results showing SPF, DKIM and DMARC status.

**Finding:**
The following suspicious headers were identified:

| Header | Value | Significance |
|--------|-------|-------------|
| X-Originating-IP | 185.220.101.45 | The actual IP the email was sent from |
| Received | mail.micros0ft-support.com | Fake mail server matching the typosquatted domain |
| X-Mailer | PHPMailer 6.0 | Bulk email tool commonly used in phishing campaigns |
| Reply-To | noreply@micros0ft-support.com | Different from From address — classic phishing indicator |

The X-Mailer value of PHPMailer 6.0 is particularly significant. Real 
Microsoft emails are sent through Microsoft's own enterprise email 
infrastructure. PHPMailer is a PHP library used to send emails from 
web servers — commonly used by attackers to automate bulk phishing 
campaigns cheaply and quickly.

---

### Step 3 — Sending IP Investigation

The originating IP address 185.220.101.45 identified in the email 
headers was submitted to AbuseIPDB for reputation analysis.

**What to look for:**
Confidence score, total reports, distinct reporting sources, IP type, 
ISP classification and attack categories in the report history.

**Finding:**
The results were extremely damning:

| Field | Detail |
|-------|--------|
| IP Address | 185.220.101.45 |
| Abuse Confidence Score | 100% |
| Total Reports | 6,567 |
| Distinct Sources | 595 organisations |
| IP Type | Tor exit node |
| ISP | Network for Tor Exit traffic |
| Hostname | tor-exit-45.tor.privacy.net |
| Country | Germany — Berlin |
| Last Reported | 14 hours before investigation |
| Attack Categories | Phishing, hacking, web attacks, brute force, SQL injection |

A 100% confidence score with over 6,500 reports from 595 different 
organisations is about as confirmed malicious as an IP can get. The 
Tor exit node classification is particularly significant — the attacker 
deliberately routed the email through the Tor anonymity network to hide 
their real location and identity. This indicates a more sophisticated 
attacker who understands operational security.

The screenshot below shows the full AbuseIPDB report confirming the 
sending IP as a known malicious Tor exit node.

![AbuseIPDB report showing 185.220.101.45 with 100% confidence score 
6567 reports and confirmed Tor exit node 
classification](screenshots/01-sending-ip-abuseipdb.png)

---

### Step 4 — Phishing Link Analysis

The malicious URL contained in the email was submitted to VirusTotal 
for reputation analysis. The URL was never clicked — it was checked 
safely through VirusTotal's URL scanning service.

**What to look for:**
Vendor detection count, URL category, domain reputation and any 
related malicious files or URLs associated with the domain.

**Finding:**
VirusTotal returned 0 detections from 96 vendors for the phishing URL. 
However this result does not clear the URL. Several factors explain 
the clean result and the URL remains highly suspicious based on 
other evidence:

- The domain was brand new and had no prior reputation in vendor databases
- VirusTotal showed "Last Analysis: a moment ago" confirming it had 
  never been scanned before
- The domain uses typosquatting — zero instead of O in Microsoft
- The .ru TLD has no legitimate association with Microsoft
- The /login path strongly suggests a credential harvesting page
- The URL contains the victim's email as a parameter confirming targeting

This is a classic example of why threat intelligence tools must be 
used together rather than relying on any single result. A clean 
VirusTotal score on a brand new phishing domain is expected — 
attackers specifically use fresh domains to avoid detection.

The screenshot below shows the VirusTotal URL analysis result.

![VirusTotal URL analysis showing 0 detections for the phishing link 
on a newly registered domain](screenshots/02-phishing-url-virustotal.png)

---

## IOC Summary

| IOC Type | Value | Verdict |
|----------|-------|---------|
| Sender domain | micros0ft-support.com | Malicious — typosquatting |
| Sending IP | 185.220.101.45 | Malicious — 100% confidence Tor exit node |
| Phishing URL | http://micros0ft-account-verify.ru/login | Malicious — credential harvesting page |
| Reply-To | noreply@micros0ft-support.com | Suspicious — matches fake domain |
| X-Mailer | PHPMailer 6.0 | Suspicious — bulk phishing tool |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Email type | Credential phishing impersonating Microsoft |
| Target | sarah.jones@securecore.com |
| Attack technique | Typosquatting, urgency tactics, credential harvesting |
| Sending IP | 185.220.101.45 — 100% malicious Tor exit node |
| Phishing domain | micros0ft-account-verify.ru |
| Goal | Steal Microsoft account credentials |
| Sophistication | Medium-High — Tor anonymisation used |
| Severity | High |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Phishing | T1566.002 | A spearphishing link was sent to a specific employee targeting their Microsoft credentials |
| Acquire Infrastructure | T1583 | The attacker registered a typosquatted domain to host the credential harvesting page |
| Hide Infrastructure | T1665 | The email was routed through a Tor exit node to anonymise the attacker's real location |
| Credentials from Web Browsers | T1555.003 | The phishing page was designed to capture Microsoft account credentials |

---

## Conclusion
This investigation confirmed a targeted credential phishing attack against 
SecureCore Ltd employee Sarah Jones. The attacker impersonated Microsoft 
using a typosquatted domain, created urgency through account suspension 
threats, and directed the victim to a Russian-hosted credential harvesting 
page designed to steal her Microsoft login details.

The use of a Tor exit node to send the email demonstrates the attacker 
understood operational security and deliberately took steps to hide their 
identity. The 100% AbuseIPDB confidence score and 6,567 reports from 595 
organisations confirms this IP is part of known malicious infrastructure 
used in multiple attack campaigns.

The clean VirusTotal result for the phishing URL highlights an important 
limitation — newly registered phishing domains specifically evade reputation 
based detection. Analysts must combine multiple data points rather than 
relying on any single tool result. In this case the typosquatted domain, 
the .ru TLD, the Tor exit node origin and the urgency tactics together 
paint an unambiguous picture of a phishing attack regardless of the 
VirusTotal score.

Sarah should be advised not to click the link. Her Microsoft credentials 
should be treated as potentially compromised if she interacted with the 
email in any way before reporting it.

## 🔑 Key Takeaways

- Always check the sender domain carefully — one character difference 
  can mean the difference between legitimate and phishing
- SPF, DKIM and DMARC failures on an email claiming to be from a major 
  company are immediate red flags
- A sending IP routed through Tor indicates a sophisticated attacker 
  deliberately hiding their identity
- A clean VirusTotal URL result does not clear a link — newly registered 
  phishing domains specifically avoid reputation databases
- Urgency and fear are the most powerful phishing tools — teach employees 
  to slow down when an email pressures them to act immediately
- Always check multiple data points together — no single tool tells 
  the complete story

---

## Recommended Actions
- Block the sending domain micros0ft-support.com at the email gateway
- Block the phishing domain micros0ft-account-verify.ru at the firewall
- Block the sending IP 185.220.101.45 at the perimeter
- Check mail server logs to confirm no other employees received 
  the same email
- Ask Sarah whether she clicked the link or entered any credentials
- If credentials were entered treat them as compromised and reset 
  immediately
- Submit the phishing domain to Microsoft for takedown
- Send a security awareness alert to all employees about this 
  phishing campaign
