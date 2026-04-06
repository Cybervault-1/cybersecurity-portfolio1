# SOC Investigation Dashboard

## Overview
This dashboard was built in Splunk to provide a combined visual summary 
of all three investigations conducted in this SOC lab. Instead of running 
queries manually each time, the dashboard displays all key findings 
automatically in one place — exactly how a real SOC analyst would monitor 
an environment for suspicious activity.

The dashboard combines data from three separate investigations:
- Case 01 — Brute Force Attack
- Case 02 — Suspicious PowerShell Activity
- Case 03 — Password Spray Attack

---

## Dashboard Panels

### Row 1 — Overview
This row gives an instant summary of the most important numbers across 
all investigations at a glance.

**Total Failed Login Attempts**
Shows the total count of failed authentication events across the brute 
force and password spray investigations combined. A high number here 
immediately signals that something is wrong in the environment.

**Total Successful Logins**
Shows the total count of successful logins. When read alongside the 
failed login count it gives a clear picture of the failed to success 
ratio — a healthy network has very few failures compared to successes.

**Encoded PowerShell Commands Detected**
Shows how many deliberately obfuscated PowerShell commands were executed 
across the environment. Any number above zero in a real environment should 
trigger an immediate investigation.

---

### Row 2 — Attack Analysis
This row identifies who was attacked and where the attacks came from.

**Failed Logins by User**
A bar chart showing which user accounts accumulated the most failed login 
attempts. In a brute force or spray attack the targeted accounts stand 
out immediately because their bars are dramatically longer than all others. 
The admin account clearly dominates this chart confirming it was the 
primary target across multiple attack scenarios.

**Failed Logins by Source IP**
A bar chart showing which IP addresses were responsible for the most 
failed login attempts. A single IP with a dramatically longer bar than 
all others confirms an automated attack tool rather than random user 
mistakes. 192.168.1.10 clearly stands out as the primary attacking IP.

---

### Row 3 — Pattern Analysis
This row shows how the attacks were distributed and when they happened.

**Login Status Breakdown**
A pie chart showing the proportion of failed versus successful logins 
across all authentication events. The larger the failed slice the more 
suspicious activity is present. In a healthy environment the success 
slice should be dominant.

**Failed Login Activity Over Time**
A line chart showing when failed login attempts happened over time. 
Spikes in the line indicate attack waves. Two separate lines represent 
the brute force log and the password spray log — allowing you to see 
both attacks plotted on the same timeline.

---

## Queries Used

**Total Failed Login Attempts:**
```
