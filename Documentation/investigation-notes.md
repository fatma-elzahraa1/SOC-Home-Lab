# Investigation Notes — Brute Force / Failed Login Alert

## Scenario

A Splunk Alert titled **"Brute Force - Failed Login Alert"** has triggered. This document walks through how a SOC L1 Analyst would triage and investigate this alert.

---

## Step 1: Confirm the Alert Details

- Open the alert in **Settings → Searches, Reports, and Alerts → Brute Force - Failed Login Alert**
- Review the **Trigger History** to confirm when it fired and how many times
- Open **"View Results"** on the most recent trigger to see the raw data that caused it

## Step 2: Identify Key Fields

For each triggered event, the analyst should extract:

| Field | Purpose |
|---|---|
| **TargetUserName** | Which account is being targeted? Is it a real user, a service account, or a decoy/honeypot account? |
| **Source IP (IpAddress)** | Where is the attempt coming from? Local (`::1` / `127.0.0.1`) or remote? Internal network or external/public IP? |
| **Host / Computer** | Which machine logged the event? Is it a critical asset (domain controller, server) or a workstation? |
| **Timestamp** | When did the activity start? How long did it last? Is it still ongoing? |
| **Count of failed attempts** | How far above the threshold is it? 6 attempts is very different from 200. |
| **Logon Type** | Was this an interactive logon (Type 2), network logon (Type 3), RDP (Type 10), or service logon? This changes the risk profile significantly. |

## Step 3: Assess Source IP

- **Loopback (`::1` / `127.0.0.1`):** Activity originated on the local machine itself. In this lab, this is expected because the simulation was run locally with `runas`. In production, this could indicate a compromised local process or a misconfigured service — still worth checking.
- **Internal/private IP (e.g., 10.x.x.x, 192.168.x.x):** Could indicate lateral movement from another compromised host inside the network — treat as higher priority.
- **External/public IP:** Indicates a potential external attacker actively attempting to authenticate — highest priority, escalate immediately.

## Step 4: Determine if the Activity Is a True Positive or False Positive

Ask:
- Is the targeted account a legitimate, active account? (In this lab, `fakeuser` is a decoy account created intentionally — in production, check if the account exists, is enabled, and who normally uses it.)
- Is this a known, scheduled process that legitimately generates failed logons (e.g., an expired service account password, a misconfigured scheduled task)?
- Does the timing correlate with any known change (e.g., a recent password reset that wasn't propagated to a service)?
- Is the source consistent with the user's normal behavior (same host, same hours), or is it anomalous?

If none of the above explain the activity, treat it as a **true positive** and escalate.

## Step 5: Check for Follow-On Success

Critical step: search for whether any of the failed attempts were followed by a **successful logon (Event ID 4624)** for the same account, from the same or a related source. A successful logon after a burst of failures is a strong indicator of a successful brute force compromise.

```spl
index=main sourcetype="XmlWinEventLog:Security" ("4624" OR "4625")
| rex field=_raw "TargetUserName'>(?<TargetUserName>[^<]+)"
| where TargetUserName="fakeuser"
| table _time, EventCode, TargetUserName
| sort _time
```

## Step 6: Containment & Response Actions (if true positive)

- Disable or lock the targeted account temporarily
- Reset the account's password if compromise is suspected
- Block the source IP at the firewall (if external/internal and not a legitimate host)
- Check the source host for signs of compromise (malware, unauthorized tools)
- Review other accounts for similar failed-logon patterns (is this part of a wider spray attack?)

## Step 7: Document Findings

Record in the incident ticket:
- Alert name and trigger time
- Targeted account(s)
- Source IP(s) and host(s)
- Number of failed attempts
- Whether a successful logon followed
- Verdict: True Positive / False Positive / Benign True Positive
- Actions taken

---

## Findings for This Lab Simulation

| Field | Value |
|---|---|
| Targeted Account | `fakeuser` |
| Failed Attempts | 18–20 |
| Source IP | `::1` (loopback — local simulation) |
| Logon Type | Local (via `runas`) |
| Follow-on Success | None observed |
| Verdict | **Benign True Positive** — detection logic correctly identified a genuine brute-force pattern; source confirmed as an intentional local simulation for lab purposes, not a real external threat. |
