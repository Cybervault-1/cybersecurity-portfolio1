
markdown# Case 02 — Malicious Link Analysis: GitHub Phishing

## Executive Summary
A phishing email impersonating GitHub was reported by a developer at 
SecureCore Ltd. The email used a typosquatted domain, an expiring link 
and SSH key notification to trick the victim into clicking a credential 
harvesting link. Investigation confirmed the email was sent through 
Telegram infrastructure — a legitimate service being abused to deliver 
phishing content. The phishing link pointed to a fake GitHub security 
page designed to steal the developer's account credentials and gain 
access to company source code and repositories.

---

## Scenario
A developer named James at SecureCore Ltd receives an email appearing 
to come from GitHub stating that a new SSH key has been added to his 
account. James does not remember adding any SSH key and immediately 
forwards the email to the SOC team. As the analyst on duty the task 
is to determine whether this is a legitimate GitHub security notification 
or a phishing attempt targeting James's developer account.

## Objective
Analyse the suspicious email to determine whether it is a phishing 
attempt, identify all malicious indicators, trace the sending 
infrastructure, check the reputation of identified IOCs, understand 
why a developer account is a high value target, and document findings 
professionally.

## Tools Used
- AbuseIPDB
- VirusTotal
- Manual email header analysis

## Email Sample
The full email sample is available in the repository:
[phishing-email.txt](phishing-email.txt)

---

## Background — Why Developer Accounts Are High Value Targets
Most phishing campaigns target regular employees to steal basic 
credentials. Targeting a developer account is significantly more 
dangerous because a developer's GitHub account contains:

- Company source code and intellectual property
- API keys and credentials hardcoded or stored in repositories
- Access to private repositories containing sensitive business logic
- Ability to push malicious code directly into production systems
- Connections to cloud infrastructure and automated deployment pipelines

A single compromised developer account can give an attacker access to 
an entire company's technical infrastructure — far beyond what a 
regular employee account would provide.

---

## Investigation Steps

### Step 1 — Initial Email Review

The email was read carefully to identify obvious red flags before 
running any tools.

**What to look for:**
Sender domain legitimacy, URL structure, urgency tactics, technical 
language designed to appear convincing and targeting of specific 
account types.

**Finding:**
Four immediate red flags were identified:

**Red Flag 1 — Typosquatted Sender Domain**
The email came from:
```
noreply@gith-ub.com
```
The real GitHub domain is github.com. This domain has a hyphen inserted 
between gith and ub — gith-ub.com. Unlike the Microsoft case which 
replaced a letter with a number, this attack inserted a hyphen which 
is even harder to spot when reading quickly. The domain gith-ub.com 
has no association with GitHub.

**Red Flag 2 — Malicious Link**
The email contained a link to:
```
http://gith-ub.com/settings/security/verify?token=xK9mP2nL&user=james.dev
```
The link uses the same fake domain as the sender. The path deliberately 
mirrors the real GitHub URL structure — /settings/security/ — to appear 
legitimate. The token and user parameters confirm this is a targeted 
attack against James specifically rather than a mass phishing campaign.

**Red Flag 3 — Urgency Tactic**
The email stated the link would expire in 1 hour. This is more 
aggressive than standard phishing which typically gives 24 hours. 
A one hour window leaves the victim almost no time to verify the 
email with IT or think carefully before clicking.

**Red Flag 4 — Fabricated SSH Key Fingerprint**
The email included what appeared to be a real SSH key fingerprint:
```
SHA256:xK9mP2nL4qR8vT1wY6zB3cD5eF7gH0iJ
```
This is designed to appear technical and convincing to a developer. 
Real GitHub SSH key fingerprints follow a specific format — this one 
is fabricated but looks plausible enough to fool someone who is 
already panicking about an unauthorised key on their account.

The screenshot below shows the full phishing email with all red flags 
visible.

![Full GitHub phishing email showing typosquatted domain, malicious 
link and urgency tactics](screenshots/03-phishing-email-content.png)

---

### Step 2 — Email Header Analysis

The technical headers were analysed to trace the sending infrastructure 
and identify the tools used to deliver the phishing email.

**What to look for:**
The originating IP address, mail server, X-Mailer tool and any 
authentication mismatches between the claimed sender and actual 
sending infrastructure.

**Finding:**
The following suspicious headers were identified:

| Header | Value | Significance |
|--------|-------|-------------|
| X-Originating-IP | 91.108.4.200 | The actual IP the email was sent from |
| Received | mail.gith-ub.com | Fake mail server matching typosquatted domain |
| X-Mailer | SendGrid 7.2 | Third party email delivery service — not GitHub infrastructure |
| Reply-To | security@gith-ub.com | Matches fake sender domain |

The X-Mailer value of SendGrid 7.2 is a significant indicator. The 
real GitHub sends security notifications through their own email 
infrastructure — not through SendGrid. Using a third party email 
delivery service suggests the attacker used a legitimate platform 
to improve deliverability and avoid spam filters.

---

### Step 3 — Sending IP Investigation

The originating IP address 91.108.4.200 was submitted to AbuseIPDB 
for reputation analysis.

**What to look for:**
Confidence score, total reports, IP type and ISP classification to 
understand what infrastructure the attacker used.

**Finding:**
| Field | Detail |
|-------|--------|
| IP Address | 91.108.4.200 |
| AbuseIPDB Status | Not found in database |
| ISP | Telegram Messenger Network |
| Usage Type | Data Center/Web Hosting/Transit |
| Domain | telegram.org |
| Country | Netherlands — Amsterdam |

The IP was not found in AbuseIPDB — meaning it has not been previously 
reported as malicious. However the ISP classification reveals something 
important. This IP belongs to Telegram's infrastructure.

This indicates the attacker abused Telegram's platform to route or 
relay the phishing email. This is a technique where attackers leverage 
legitimate and trusted services to deliver malicious content — making 
it harder to block because the traffic appears to originate from a 
reputable platform.

A clean AbuseIPDB result does not clear this IP. The context of the 
full investigation — combined with the typosquatted domain, fake 
GitHub branding and credential harvesting link — confirms this is 
a phishing attack regardless of the IP reputation score.

The screenshot below shows the AbuseIPDB result for the sending IP.

![AbuseIPDB result showing sending IP belongs to Telegram infrastructure 
with no prior abuse reports](screenshots/01-sending-ip-abuseipdb.png)

---

### Step 4 — Phishing Link Analysis

The malicious URL was submitted to VirusTotal for reputation analysis 
without clicking it directly.

**What to look for:**
Vendor detection count, domain reputation, last analysis date and 
any related malicious infrastructure associated with the domain.

**Finding:**
VirusTotal returned 0 detections from 96 vendors for the phishing URL. 
The Last Analysis Date showed "a moment ago" confirming the domain had 
never been scanned before this investigation.

As with Case 01 this clean result is expected and does not clear the 
URL. Attackers specifically register fresh domains to avoid reputation 
based detection. The following evidence confirms the URL is malicious 
regardless of the VirusTotal result:

- Domain gith-ub.com uses typosquatting with an inserted hyphen
- The path /settings/security/verify mirrors legitimate GitHub URLs 
  to appear convincing
- The token and user parameters confirm targeted credential harvesting
- The domain has no legitimate association with GitHub

The screenshot below shows the VirusTotal URL analysis result.

![VirusTotal URL analysis showing 0 detections for newly registered 
phishing domain](screenshots/02-phishing-url-virustotal.png)

---

## IOC Summary

| IOC Type | Value | Verdict |
|----------|-------|---------|
| Sender domain | gith-ub.com | Malicious — typosquatting |
| Sending IP | 91.108.4.200 | Suspicious — Telegram infrastructure abuse |
| Phishing URL | http://gith-ub.com/settings/security/verify | Malicious — credential harvesting |
| X-Mailer | SendGrid 7.2 | Suspicious — not GitHub infrastructure |
| Reply-To | security@gith-ub.com | Suspicious — matches fake domain |

---

## Findings Summary

| Finding | Detail |
|---------|--------|
| Email type | Credential phishing impersonating GitHub |
| Target | james.dev@securecore.com — developer account |
| Attack technique | Typosquatting, SSH key notification lure, urgency |
| Sending IP | 91.108.4.200 — Telegram infrastructure |
| Phishing domain | gith-ub.com |
| Goal | Steal GitHub credentials and access company repositories |
| Sophistication | Medium-High — legitimate service abuse and technical lure |
| Severity | Critical — developer account with repository access |

---

## MITRE ATT&CK Mapping

| Technique | ID | What was observed |
|-----------|-----|------------------|
| Phishing | T1566.002 | A spearphishing link was sent targeting a specific developer's GitHub credentials |
| Acquire Infrastructure | T1583 | The attacker registered a typosquatted domain mimicking GitHub to host the credential harvesting page |
| Abuse Legitimate Services | T1102 | Telegram infrastructure was abused to send the phishing email making it harder to detect and block |
| Valid Accounts | T1078 | The goal was to obtain valid GitHub credentials to access company source code and repositories |
| Supply Chain Compromise | T1195 | A compromised developer account could allow injection of malicious code into company repositories |

---

## Conclusion
This investigation confirmed a targeted credential phishing attack 
against SecureCore Ltd developer James. The attacker impersonated 
GitHub using a typosquatted domain with an inserted hyphen, fabricated 
an SSH key security alert to create concern, and directed the victim 
to a fake GitHub security page designed to steal his credentials.

The use of Telegram infrastructure to deliver the email demonstrates 
the attacker's understanding of how to abuse legitimate services to 
bypass security controls. By routing the email through Telegram the 
attacker avoided IP-based blocking since Telegram is a trusted platform 
used legitimately by many organisations.

This case is rated critical severity because a compromised developer 
GitHub account represents significantly more risk than a standard 
employee account. Access to company repositories could allow the 
attacker to steal source code, extract embedded credentials and API 
keys, and potentially inject malicious code into production systems 
— turning a credential theft into a full supply chain compromise.

The clean results from both AbuseIPDB and VirusTotal highlight again 
that tool results must never be the sole basis for a verdict. The 
combination of typosquatted domain, fake GitHub branding, Telegram 
infrastructure abuse and targeted credential harvesting parameters 
tells an unambiguous story regardless of reputation scores.

## 🔑 Key Takeaways

- Hyphens in domain names are just as suspicious as number 
  substitutions — typosquatting takes many forms
- Developer accounts are critical assets — phishing targeting 
  developers should always be treated as high severity
- Attackers abuse legitimate services like Telegram to bypass 
  IP reputation blocking — a clean AbuseIPDB result does not 
  mean the infrastructure is safe
- Fabricated technical details like fake SSH fingerprints are 
  designed to exploit the victim's domain knowledge and make 
  the attack more convincing
- A one hour expiry is more aggressive than standard phishing — 
  the shorter the deadline the more likely the victim acts 
  without thinking
- Supply chain risk must always be considered when developer 
  accounts are targeted

---

## Recommended Actions
- Block the sender domain gith-ub.com at the email gateway
- Block the phishing domain gith-ub.com at the firewall
- Ask James whether he clicked the link or entered any credentials
- If credentials were entered treat his GitHub account as 
  compromised immediately
- Rotate all API keys and tokens stored in James's repositories
- Review all recent commits to company repositories for 
  unauthorised changes
- Enable two-factor authentication on all developer GitHub accounts
- Check mail server logs for other employees who may have 
  received the same email
- Submit the phishing domain to GitHub for takedown
- Brief the development team on GitHub phishing awareness
