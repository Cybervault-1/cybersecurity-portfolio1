# IR-003 — Password Spray Attack Against Multiple User Accounts

**Incident ID:** IR-003
**Date Reported:** 2026-04-10
**Date Resolved:** 2026-04-10
**Severity:** Critical
**Status:** Closed
**Analyst:** Adetayo Adedeji

---

## 1. Incident Summary

A password spray attack was detected against SecureCore Ltd targeting 
9 user accounts simultaneously from a single IP address 192.168.1.77. 
The attacker deliberately kept attempts to 2 per account to stay under 
the lockout threshold and avoid triggering any alerts. The attack 
succeeded against one account whose password matched the spray guess. 
After getting in the attacker moved across 5 internal servers including 
the domain controller and backup server within 68 minutes.

---

## 2. Timeline of Events

| Date/Time | Event |
|-----------|-------|
| 2026-04-10 14:00:01 | First spray wave begins. All 9 accounts hit once in quick succession |
| 2026-04-10 14:01:04 | Second spray wave begins. All accounts hit a second time |
| 2026-04-10 14:02:00 | Third spray wave begins |
| 2026-04-10 14:02:07 | jsmith account breached. Summer2026! matches real password |
| 2026-04-10 14:02:07 | Attacker accesses domain controller at 10.0.0.5 using jsmith credentials |
| 2026-04-10 14:10:00 | Attacker accesses file server at 10.0.0.20 |
| 2026-04-10 14:15:00 | Attacker accesses backup server at 10.0.0.30 |
| 2026-04-10 15:00:00 | Attacker accesses unknown server at 10.0.0.40 |
| 2026-04-10 15:05:00 | Attacker accesses unknown server at 10.0.0.50 |
| 2026-04-10 15:10:00 | Attacker returns to file server at 10.0.0.20 |
| 2026-04-10 15:30:00 | Incident detected and investigation initiated |

---

## 3. Affected Systems

| System | IP Address | Role | Impact |
|--------|------------|------|--------|
| Domain Controller | 10.0.0.5 | Manages all accounts and permissions | Accessed by attacker |
| File Server | 10.0.0.20 | Stores company files | Accessed twice by attacker |
| Backup Server | 10.0.0.30 | Stores all system backups | Accessed by attacker |
| Unknown Server | 10.0.0.40 | Role under investigation | Accessed by attacker |
| Unknown Server | 10.0.0.50 | Role under investigation | Accessed by attacker |

---

## 4. Evidence Collected

| Evidence | Detail |
|----------|--------|
| Authentication logs | 30 total events across brute force and spray log files |
| Attacking IP | 192.168.1.77 responsible for all 18 failed login attempts |
| Accounts targeted | 9 accounts each receiving exactly 2 failed attempts |
| Compromised account | jsmith with password Summer2026! |
| Lateral movement | 7 successful logins across 5 servers within 68 minutes |
| Spray pattern | Synchronized waves confirmed via Splunk timechart visualization |

---

## 5. Root Cause Analysis

The attack succeeded because of three security failures.

**Primary Cause: Weak Password Policy**
The user jsmith had a weak seasonal password Summer2026! that the 
attacker correctly guessed. Seasonal passwords like Summer2026!, 
Winter2025! and Welcome123! are among the first passwords tried in 
spray attacks because they follow predictable patterns. The organisation 
had no password policy in place to prevent employees from using 
weak or common passwords.

**Secondary Cause: No Multi-Factor Authentication**
The jsmith account had no multi-factor authentication enabled. Even 
after guessing the correct password, MFA would have prevented the 
attacker from completing the login. A correct password alone was 
enough to gain access to the account and everything connected to it.

**Contributing Factor: No Detection for Spray Patterns**
The organisation had no SIEM alert configured to detect a single IP 
hitting multiple accounts within a short time window. Each account 
only showed 2 failures which is below any standard lockout threshold. 
Without a cross-account detection rule the attack went unnoticed until 
the damage was already done.

---

## 6. Containment Actions

Actions taken to stop the attack from spreading:

- Disabled jsmith account immediately
- Blocked 192.168.1.77 at the perimeter firewall
- Isolated all 5 affected servers pending investigation
- Forced immediate password reset for all 9 targeted accounts
- Reviewed all other accounts for signs of compromise

---

## 7. Eradication Actions

Actions taken to remove the threat completely:

- Verified no unauthorised accounts were created on any affected server
- Reviewed domain controller logs for any permission changes made 
  during the breach window
- Checked all 5 affected servers for signs of malware or 
  persistence mechanisms
- Verified backup server integrity and confirmed backups were not 
  modified or deleted
- Investigated the role and content of servers 10.0.0.40 and 10.0.0.50 
  to determine what data the attacker may have accessed

---

## 8. Recovery Actions

Actions taken to restore normal operations:

- Re-enabled jsmith account with a new strong password after MFA 
  was confirmed active
- Restored all affected servers to normal operation after forensic 
  review confirmed no persistence
- Verified all critical services were functioning normally
- Confirmed backup integrity before resuming normal backup operations
- Monitored all affected systems closely for 72 hours post-recovery

---

## 9. Recommendations

| Priority | Recommendation |
|----------|---------------|
| Critical | Enable multi-factor authentication on all accounts starting with privileged ones |
| Critical | Implement and enforce a strong password policy that blocks seasonal and common passwords |
| High | Create a SIEM alert for any single IP hitting more than 3 accounts within 60 seconds |
| High | Force an organisation-wide password reset immediately |
| High | Investigate servers 10.0.0.40 and 10.0.0.50 to confirm what data was accessed |
| Medium | Set account lockout to trigger after 3 failed attempts |
| Medium | Conduct employee security awareness training focused on password security |
| Low | Review and classify all internal servers to ensure their roles are documented |

---

## 10. Lessons Learned

This attack worked because it was designed specifically to avoid 
detection. By keeping attempts to exactly 2 per account the attacker 
stayed below every standard security threshold. No single account 
looked suspicious on its own. The attack only became visible when 
all accounts were looked at together.

The speed of the lateral movement was alarming. Within 8 minutes of 
guessing jsmith's password the attacker was already on the domain 
controller. By the end of the first hour they had touched 5 servers. 
This shows how quickly a single compromised account can turn into a 
full network breach when basic controls are not in place.

The backup server access is the finding that raised the most concern. 
Attackers commonly destroy backups before launching ransomware to 
remove the victim's ability to recover. The fact that the attacker 
reached the backup server means ransomware deployment was a real 
possibility that was narrowly avoided.

Key lessons from this incident:

- Password spraying is invisible at the individual account level. 
  Detection requires looking across all accounts at the same time.
- One weak password on one account was enough to reach 5 servers 
  including the domain controller. Password strength affects the 
  entire organisation, not just one user.
- The gap between breach and lateral movement was 8 minutes. Fast 
  detection and response is critical because attackers move quickly 
  once they are inside.
- Backup server access must always trigger an immediate integrity 
  check. If backups are destroyed recovery from ransomware becomes 
  extremely difficult.
- MFA on all accounts is the single most effective control against 
  credential based attacks like password spraying.

---

## 11. References

- [Splunk Investigation — Case 03 Password Spray Detection](../../02-splunk-siem-lab/case-03-failed-logins-spike/README.md)
- MITRE ATT&CK T1110.003 — Password Spraying
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1021 — Lateral Movement via Remote Services
