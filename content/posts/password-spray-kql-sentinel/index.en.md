---
title: "How to spot password spray with KQL in Microsoft Sentinel"
date: 2026-11-12
draft: false
description: "What password spray is, why the built-in Entra ID protections do not show the attempts that fail, and how to find them in the sign-in logs with KQL."
summary: "What password spray is, why the built-in protections do not show the attempts that fail, and how to find them in the sign-in logs with KQL."
categories: ["Detection"]
tags: ["kql", "sentinel", "entra id", "identity"]
nivel: "intermediario"
featured: true
mitre:
  - { tatica: "TA0006", tecnica: "T1110.003", nome: "Password Spraying" }
---

In a password spray attack, the adversary tries one common password, or a small list of passwords, against many different accounts. MITRE ATT&CK catalogs the technique as [T1110.003](https://attack.mitre.org/techniques/T1110/003/) and explains the reason for that choice: the attempts are spread across many accounts to avoid the lockout that would follow from hammering a single account. The same page notes that single sign-on services and cloud applications are among the targets, and that adversaries may deliberately throttle the attempts to avoid triggering alerts.

This post shows how to look for that pattern in the Microsoft Sentinel `SigninLogs` table, what the query sees and what it misses.

## Why the built-in protections are not enough

Entra ID already ships two defenses worth understanding before writing any query.

**Smart lockout.** [Smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout) is always on. By default, an account is locked after 10 failed attempts in Azure Public tenants, and the first lockout lasts one minute. The counter is per account. A spray that tries one or two passwords per account stays far below that threshold. Microsoft's [investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray) calls this a "low and slow" attack: the thresholds for account lockout or bad passwords are not being hit.

**Risk detection.** Microsoft Entra ID Protection has a [detection named Password spray](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), which requires a Microsoft Entra ID P2 license. The documentation is explicit about its reach: the detection is only triggered when an attacker successfully validates a user's password, and unsuccessful spray attempts do not generate a detection.

In other words, the phase in which the attack is still failing is only visible to those who query the sign-in logs.

## The query

The idea is simple: one IP address failing to sign in to many different accounts within a short window.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053")
| summarize Users = dcount(UserPrincipalName), Attempts = count()
    by IPAddress, bin(TimeGenerated, 1h)
| where Users >= 10
| order by Users desc
```

Line by line:

- `ResultType` is the column of the [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) that holds the sign-in error code. The value `0` indicates success and the others are failures. The column is a string, which is why the codes are quoted.
- `50126` is the [invalid username or password](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes) error. `50053` shows up when the account is locked after too many attempts, or when the sign-in was blocked because it came from an IP address with malicious activity.
- [`bin(TimeGenerated, 1h)`](https://learn.microsoft.com/en-us/kusto/query/bin-function) rounds the time down into one-hour blocks, to group the attempts per window.
- [`dcount(UserPrincipalName)`](https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function) counts how many different accounts each IP tried. The function returns an estimate, trades accuracy for performance and may vary between executions. For a threshold like 10 this does not change the conclusion, but it is good to know.
- `Users >= 10` and the one-hour window are starting points, not official values. Tune both to the volume of your environment.

<!-- Alessandro: add here the result of the query in your lab environment, with fictitious or anonymized data, and the thresholds that worked for you. -->

## Was the password found?

Finding a suspicious IP answers only half of the question. Microsoft's playbook separates two outcomes:

- **Password compromise:** the attacker guessed the password but has not been able to access the account because of other controls, such as multifactor authentication.
- **Account compromise:** the attacker guessed the password and gained access.

The second query starts from the IPs found and looks for sign-ins that did not end in a wrong password:

```kql
let SuspectIPs = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType in ("50126", "50053")
    | summarize Users = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
    | where Users >= 10
    | distinct IPAddress;
SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress in (SuspectIPs)
| where ResultType in ("0", "50074", "50076")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, AppDisplayName
| order by TimeGenerated asc
```

The value `0` is a completed sign-in from an IP that was spraying, the most serious case. Codes `50074` and `50076` indicate that the sign-in stopped at the multifactor authentication requirement: the investigation playbook lists `50074` as "MFA required", and the error code reference describes `50076` as MFA being required by a policy such as Conditional Access. Treat those accounts as password compromise candidates until proven otherwise.

<!-- Alessandro: confirm in your environment how these codes show up when the password is correct and MFA stops the access, and add your experience with this kind of investigation. -->

## What the query does not see

- **Distributed spray.** The query groups by IP address. An attack that switches IPs every few attempts does not show up. In that case, try grouping by other columns of the same table, such as `UserAgent`, `Location` or `AppDisplayName`.
- **Very slow pace.** If the attempts are spaced more than an hour apart, each window will hold few accounts. A larger `bin` window helps, at the cost of more noise.
- **Non-interactive sign-ins.** They live in another table, [`AADNonInteractiveUserSignInLogs`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs), and the query above does not work there without changes. In that table, `ResultType` holds the result of the operation and the error code is in `ResultSignature`.
- **Shared legitimate IPs.** Before concluding that an IP belongs to the attacker, check that it is not a network egress of your own organization or of a partner.

## How to respond

Microsoft's investigation playbook recommends, among other actions:

1. Change the password of any account suspected of being breached or whose password was discovered.
2. Block the attacker's IP address, with care: the playbook warns that attackers can use legitimate VPNs.
3. Block legacy authentication if it is in use, weighing the business impact.
4. Enable multifactor authentication if it is not already enabled.
5. Enable Identity Protection for user risk and sign-in risk.
6. Implement [password protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad) with the custom banned password list. The global list is applied automatically to all users in the tenant, and the custom list accepts up to 1,000 terms.

MITRE ATT&CK lists three mitigations for the technique: multifactor authentication (M1032), account use policies with lockout after failures (M1036) and password policies (M1027).

## Conclusion

Password spray is designed to stay below lockout thresholds, and the built-in risk detection only warns once a password has been validated. The query for one IP failing on many accounts covers the period before that, and the second query tells you which accounts need immediate attention. Both are in the site's [KQL library]({{< relref "/kql" >}}).

## References

- MITRE ATT&CK. [Brute Force: Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)
- Microsoft Learn. [Password spray investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray)
- Microsoft Learn. [Protect user accounts from attacks with Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- Microsoft Learn. [What are risk detections?](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- Microsoft Learn. [Eliminate bad passwords using Microsoft Entra Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad)
- Microsoft Learn. [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [AADNonInteractiveUserSignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- Microsoft Learn. [dcount() aggregation function](https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function) and [bin() function](https://learn.microsoft.com/en-us/kusto/query/bin-function)
