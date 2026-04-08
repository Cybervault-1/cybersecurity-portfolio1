# IR-001 — Brute Force Attack Against Admin Account

**Incident ID:** IR-001
**Date Reported:** 2026-04-01
**Date Resolved:** 2026-04-06
**Severity:** Critical
**Status:** Closed
**Analyst:** Adetayo Adedeji

---

## 1. Incident Summary

A brute force attack was launched against the admin account at SecureCore 
Ltd resulting in two confirmed breaches five days apart. The attacker at 
IP 192.168.1.10 made repeated automated authentication attempts against 
the domain controller exploiting the absence of an account lockout policy. 
Following the initial breach the attacker returned five days later and 
moved laterally across three critical servers including the domain 
controller, file server and backup server.

---

## 2. Timeline of Events

| Date/Time | Event |
|-----------|-------|
| 2026-04-01 10:00:01 | Multiple failed login attempts begin against admin account from 192.168.1.10 |
| 2026-04-01 10:01:00 | Admin account successfully breached — first confirmed breach |
| 2026-04-01 10:30:00 | Second IP 192.168.1.99 appears making 3 unknown login attempts |
| 2026-04-01 10:30:20 | Activity from 192.168.1.99 stops — no successful login |
| 2026-04-06 09:58:01 | Attacker returns — second wave of brute force attempts begins |
| 2026-04-06 10:00:03 | Admin account breached again — second confirmed breach |
| 2026-04-06 10:30:00 | Attacker accesses domain controller at 10.0.0.5 |
| 2026-04-06 10:45:00 | Attacker accesses file server at 10.0.0.20 |
| 2026-04-06 10:47:00 | Attacker accesses backup server at 10.0.0.30 |
| 2026-04-06 11:00:00 | Incident detected and investigation initiated |

---

## 3. Affected Systems

| System | IP Address | Role | Impact |
|--------|------------|------|--------|
| Domain Controller | 10.0.0.5 | Manages all user accounts and permissions | Accessed by attacker |
| File Server | 10.0.0.20 | Stores company files and documents | Accessed by attacker |
| Backup Server | 10.0.0.30 | Stores all system backups | Accessed by attacker |

---

## 4. Evidence Collected

| Evidence | Detail |
|----------|--------|
| Authentication logs | Windows login event logs showing 33 failed attempts and 5 successful logins |
| Attacking IP | 192.168.1.10 — primary attacker |
| Secondary IP | 192.168.1.99 — unknown login attempts 29 minutes after breach |
| Event codes | EventCode 4625 — failed login, EventCode 4624 — successful login |
| Lateral movement | Successful logins to 3 different servers within 47 minutes |
| Tool used | Automated brute force tool confirmed by attempt frequency |

---

## 5. Root Cause Analysis

The attack succeeded because of two fundamental security failures:

**Primary Cause — No Account Lockout Policy**
The organisation had no account lockout policy in place. A standard 
lockout after 5 failed attempts would have blocked the attack before 
it succeeded — preventing the breach entirely. The absence of this 
basic control allowed the attacker to make unlimited authentication 
attempts without interruption.

**Secondary Cause — No Multi-Factor Authentication**
The admin account had no multi-factor authentication enabled. Even 
if an attacker correctly guesses a password MFA would prevent them 
from completing authentication without the second factor. A correct 
password alone was sufficient to gain full privileged access to the 
entire network.

**Contributing Factor — Incomplete First Remediation**
The attacker returned five days after the initial breach and succeeded 
again through the same method. This confirms the original incident 
response was incomplete — the admin credentials were not fully reset 
and the attack path was not properly closed after the first breach.

---

## 6. Containment Actions

Actions taken to stop the attack from spreading further:

- Disabled the compromised admin account immediately
- Blocked 192.168.1.10 and 192.168.1.99 at the perimeter firewall
- Isolated all three affected servers from the network pending 
  forensic investigation
- Reset all admin credentials across the environment
- Forced password reset for all privileged accounts

---

## 7. Eradication Actions

Actions taken to remove the threat completely:

- Verified no unauthorised accounts were created on any affected server
- Checked all affected servers for signs of malware or persistence 
  mechanisms left by the attacker
- Reviewed all admin account activity between April 1st and April 6th 
  for any unauthorised changes
- Verified backup server integrity — confirmed backups were not 
  modified or deleted
- Removed attacker IP addresses from all network access lists

---

## 8. Recovery Actions

Actions taken to restore normal operations safely:

- Re-enabled admin account with new strong credentials after MFA 
  was confirmed active
- Restored affected servers to normal operation after forensic 
  review confirmed no persistence
- Verified all critical services were functioning normally
- Confirmed backup integrity before resuming normal backup operations
- Monitored all affected systems closely for 72 hours post-recovery

---

## 9. Recommendations

| Priority | Recommendation |
|----------|---------------|
| Critical | Implement account lockout policy — lock after 5 failed attempts for 30 minutes |
| Critical | Enable multi-factor authentication on all privileged accounts immediately |
| High | Implement real-time SIEM alerting for more than 5 failed logins within 60 seconds |
| High | Conduct regular privileged account access reviews |
| Medium | Implement privileged access workstations for admin account usage |
| Medium | Enable detailed audit logging on all domain controllers |
| Low | Conduct security awareness training for all IT staff on incident response procedures |

---

## 10. Lessons Learned

This incident demonstrated that the most damaging breaches are often 
caused by missing basic security controls rather than sophisticated 
attacks. The attacker did not use any advanced techniques — they simply 
kept trying passwords until one worked because nothing was in place to 
stop them.

The return attack five days later was entirely preventable. A proper 
incident response process would have included full credential rotation, 
verification that the attack path was closed and monitoring to confirm 
the attacker had no remaining access. The incomplete first response 
gave the attacker a second opportunity to cause significantly more damage.

Key lessons:
- Basic controls like account lockout and MFA must be in place 
  before an incident occurs — they cannot be retrofitted during one
- Incident response must be thorough — a partial fix is as dangerous 
  as no fix because it creates a false sense of security
- Lateral movement happens fast — the attacker reached three critical 
  servers within 47 minutes of the second breach
- Backup server access must always be treated as a ransomware risk 
  requiring immediate integrity verification

---

## 11. References

- [Splunk Investigation — Case 01 Brute Force Detection](../../02-splunk-siem-lab/case-01-brute-force-detection/README.md)
- MITRE ATT&CK T1110.001 — Brute Force Password Guessing
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1021 — Remote Services Lateral Movement
