# Wazuh SOC Analyst Challenge: Incident Investigation Report

> Hands-on SOC investigation completed with Wazuh, following the \[MyDFIR Wazuh SOC Analyst Challenge](https://www.youtube.com/playlist?list=PLHmErnFy\_2zk) (9-part series).

**Analyst:** \[Your Name]
**Tools:** Wazuh (SIEM/XDR), \[add: Wazuh Dashboard, Discover, File Integrity Monitoring, Threat Hunting module, etc.]
**Date completed:** \[Month DD, YYYY]
**Case status:** Closed / Recommendations issued

\---

## Overview

I built a small home SOC lab around Wazuh and used it to investigate simulated attacker activity end to end. The scenario included SSH abuse against a Linux endpoint, account changes, and file deletion. I triaged the alerts in the Wazuh dashboard, built a timeline from the logs, identified the affected hosts and accounts, and documented my findings and recommendations in the incident report below.

**Goals:**

* Practice the SOC workflow: detect, triage, investigate, report
* Analyze authentication logs and File Integrity Monitoring (FIM) alerts
* Answer the core investigation questions (who, what, when, where, why, how)
* Write clear, actionable recommendations for containment and prevention

**Tools used:** Wazuh (Manager, Indexer, Dashboard, Agent), \[Kali Linux, Hydra/Nmap, Ubuntu, VirtualBox/VMware: edit to match your lab]

\---

## Lab Architecture

!\[Wazuh SOC Lab Architecture](screenshots/architecture.svg)

|Component|Role|OS / Details|IP|
|-|-|-|-|
|Attacker|Generates SSH attack traffic|\[Kali Linux VM]|\[x.x.x.x]|
|Monitored endpoint|Target host running the Wazuh agent (auth logs + FIM)|\[Ubuntu Linux VM]|\[x.x.x.x]|
|Wazuh server|Manager, indexer and dashboard; receives events and raises alerts|\[Ubuntu / Wazuh OVA]|\[x.x.x.x]|
|Analyst workstation|Browser access to the Wazuh dashboard for investigation|\[Host machine]|\[x.x.x.x]|

**Data flow:** Attacker traffic reaches the endpoint over SSH (TCP 22). The Wazuh agent forwards authentication logs and FIM events to the Wazuh manager (TCP 1514). Rules generate alerts, which I triage and investigate in the dashboard over HTTPS (443).

\---

## 1\. Findings

Summary of what the evidence showed. Replace the bracketed items with what you saw in your own lab.

|Investigation Question|Answer|
|-|-|
|What happened?|\[e.g., Repeated failed SSH logins against `<account>` from `<source IP>`, followed by a successful login, a new local account creation, and file deletion]|
|When did it happen?|\[First event: YYYY-MM-DD HH:MM:SS TZ → Last event: YYYY-MM-DD HH:MM:SS TZ]|
|Which hosts were involved?|Source/attacker: \[IP/hostname]. Target: \[agent name / IP / OS]|
|Which accounts were changed?|\[account(s) created, modified, or added to groups (e.g., sudo)]|
|Was a file deleted?|\[Yes/No. Path: `/path/to/file`, deleted by `<user>` at `<time>`. Detected by rule ID `<553 or other>`]|
|Was SSH abuse observed?|\[Yes/No. # of failed attempts: `<n>`, rule ID(s): `<5710 / 5712 / 5763 / etc.>`, targeted user(s): `<...>`]|
|What should we recommend?|See [Recommendations](#5-recommendations)|

### Key Indicators of Compromise (IOCs)

|Type|Value|Notes|
|-|-|-|
|Source IP|\[x.x.x.x]|Origin of SSH attempts|
|Targeted account|\[username]||
|New/modified account|\[username]||
|Deleted file|\[/path/file]||
|Wazuh rule IDs|\[5710, 5712, 5763, 553, 5902 ...]||

\---

## 2\. Investigation Summary

*What happened, in plain language (one short paragraph, then a timeline).*

\[Write 3–5 sentences. Example structure: "Wazuh generated a spike of authentication failure alerts on `<host>` originating from `<IP>`. Pivoting on the source IP showed `<n>` failed SSH attempts against `<account>` over `<duration>`, followed by a successful login at `<time>`. Shortly afterward, a new user `<name>` was created, and `<file>` was deleted from `<path>`."]

### Timeline of Events

|Time (TZ)|Host|Event|Wazuh Rule / Source|
|-|-|-|-|
|\[HH:MM:SS]|\[host]|\[First failed SSH login]|\[rule ID]|
|\[HH:MM:SS]|\[host]|\[Brute-force threshold reached]|\[rule ID]|
|\[HH:MM:SS]|\[host]|\[Successful SSH login]|\[rule ID]|
|\[HH:MM:SS]|\[host]|\[New user account created]|\[rule ID]|
|\[HH:MM:SS]|\[host]|\[File deleted]|\[rule ID / FIM]|

\---

## 3\. Who, What, When, Where, Why, How

|||
|-|-|
|**Who**|Source: \[attacker IP]. Targeted account(s): \[...]. Accounts created/changed: \[...].|
|**What**|\[SSH brute force → unauthorized access → account creation → file deletion]|
|**When**|Started \[date/time, TZ]. Ended \[date/time, TZ]. Ongoing? \[Yes/No, and how you confirmed]|
|**Where**|Host \[agent name/IP/OS]. Services: SSH (port 22). Paths: \[...]|
|**Why**|\[If known: credential access, persistence, cover tracks. If unknown, say "Not determined from available logs; likely ..."]|
|**How**|\[Password guessing against SSH → valid credentials → created persistence account → deleted file to remove evidence]|

\---

## 4\. Evidence \& Methodology

*Add screenshots from your lab to `/screenshots` and reference them here.*

1. **Detection:** \[How the alert surfaced in the Wazuh dashboard]
`!\[Alert overview](screenshots/01-alerts.png)`
2. **SSH abuse analysis:** \[Filters used, e.g. `rule.groups: authentication\_failed`, `data.srcip: x.x.x.x`]
`!\[SSH failures](screenshots/02-ssh-failures.png)`
3. **Account changes:** \[Events showing user/group creation or modification]
`!\[Account creation](screenshots/03-account.png)`
4. **File deletion:** \[FIM or audit event showing path, user, and time]
`!\[File deletion](screenshots/04-file-deleted.png)`

\---

## 5\. Recommendations

**Immediate (contain):**

* Block source IP `\[x.x.x.x]` at the firewall; consider Wazuh active response (`firewall-drop`) for repeated SSH failures.
* Disable or remove the unauthorized account `\[username]` and review its group memberships and `sudoers` entries.
* Reset credentials for `\[targeted account]` and terminate any active sessions from the attacker IP.
* Restore or investigate the deleted file `\[path]` from backup and review what it contained.

**Short term (eradicate/recover):**

* Review `/var/log/auth.log` and shell history for any additional attacker activity after login.
* Hunt other hosts for the same source IP and for similar account-creation events.

**Long term (reduce risk):**

* Disable SSH password authentication and require key-based auth; disable direct root login.
* Enforce MFA for remote access and restrict SSH to a VPN or allow-listed IPs.
* Deploy Fail2ban or Wazuh active response to throttle brute force.
* Expand File Integrity Monitoring coverage and alert on account creation and privilege changes.
* Tune alert thresholds so repeated authentication failures escalate quickly.

\---

## 6\. Skills Demonstrated

SIEM alert triage · Log analysis · SSH brute-force detection · File Integrity Monitoring · Account-change investigation · Incident reporting

## 7\. Repo Structure

```
.
├── README.md
├── screenshots/
└── queries/        # optional: saved Wazuh/Discover filters used
```

## Credits

Lab guidance by [MyDFIR](https://www.youtube.com/playlist?list=PLHmErnFy_2zk). Analysis and write-up are my own.

