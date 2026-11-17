---
title: "MFA registration as persistence in Entra ID: detect, respond and protect"
date: 2026-11-17
draft: false
description: "How an attacker holding a user's password registers their own MFA method to keep access, how to find those registrations in Entra ID audit logs with KQL, and how to protect security info registration with Conditional Access."
summary: "How attackers register their own MFA to keep access, how to find those registrations with KQL in Sentinel, and how to protect registration with Conditional Access."
categories: ["Identity"]
tags: ["entra id", "mfa", "conditional access", "kql", "sentinel"]
series: ["KQL detections"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0003", tecnica: "T1098.005", nome: "Device Registration" }
  - { tatica: "TA0004", tecnica: "T1098.005", nome: "Device Registration" }
---

When a password leaks, MFA is usually the last barrier. But there is a moment when that barrier does not exist yet: the account that never registered a method. MITRE ATT&CK describes the problem in [Account Manipulation: Device Registration (T1098.005)](https://attack.mitre.org/techniques/T1098/005/): an adversary who compromises a user's credentials may enroll a new device to bypass initial MFA requirements and gain persistent access. The same page notes that the MFA self-enrollment process may require only a username and password to enroll the account's first device.

The outcome is worse than a single sign-in. After registration, the second factor is in the attacker's hands, and resetting the victim's password is not enough to remove them if their method stays registered.

This article shows where that registration appears in Entra ID logs, two KQL queries for Sentinel, how to react when a registration is suspicious, and how to reduce the attack surface with Conditional Access.

## Who uses the technique

The MITRE technique page lists as procedure examples APT29, which according to MITRE enrolled its own devices into compromised cloud tenants, campaign C0027, attributed to Scattered Spider, the SolarWinds Compromise campaign and the AADInternals tool. The technique covers two tactics: Persistence (TA0003) and Privilege Escalation (TA0004).

## Where registration shows up

The [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities) has an "Authentication Methods" section, and the page itself says these logs can be used to make sure users registered their mobile device properly for MFA. The listed activities, all in the UserManagement category, include:

| Activity | What it means |
| --- | --- |
| User registered security info | The user registered a method themselves |
| User registered all required security info | The user completed the required registration |
| User changed default security info | The default method was changed |
| User deleted security info | The user removed a method |
| User updated security info | The user changed an existing method |
| Admin registered security info | An administrator registered a method for someone |
| Admin updated security info | An administrator changed a method |
| Admin deleted security info | An administrator removed a method |

In Sentinel, these events land in the [AuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs) table, which has, among others, the columns `OperationName`, `Result`, `ResultReason`, `InitiatedBy`, `TargetResources` and `CorrelationId`. `InitiatedBy` and `TargetResources` are `dynamic`, so the queries below extract the inner fields with `tostring()`.

## Query 1: method changes in the last 7 days

The first query lists who registered, changed or removed authentication methods, from which IP address and for which account. It is a starting point for manual review and for understanding normal volume before creating any alert.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("User registered security info", "User changed default security info",
    "User deleted security info", "User updated security info",
    "Admin registered security info", "Admin updated security info", "Admin deleted security info")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
    ActorIp = tostring(InitiatedBy.user.ipAddress),
    TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Result, ResultReason, Actor, ActorIp, TargetUser, CorrelationId
| order by TimeGenerated desc
```

Three situations deserve a closer look: an account that changes its default method right after registering a new one, an administrator registering methods for users outside a known process, and many registrations from the same IP for different accounts. These criteria are my own triage suggestions, not official rules.

<!-- Alessandro: query not run in a real environment. Confirm that OperationName carries exactly the names from the audit reference and note which TargetResources and ResultReason fields show the registered method type. -->

## Query 2: registration from an IP the account never used

The second query looks for the typical account-takeover case: the user registers a method from an IP address that did not appear in any successful sign-in by that same account in the previous 30 days. The 1-day and 30-day windows are my own starting points; adjust them to your workspace retention.

```kql
let lookback = 30d;
let window = 1d;
let Registrations = AuditLogs
| where TimeGenerated > ago(window)
| where OperationName == "User registered security info"
| extend TargetUser = tolower(tostring(TargetResources[0].userPrincipalName)),
    IPAddress = tostring(InitiatedBy.user.ipAddress)
| where isnotempty(IPAddress)
| project TimeGenerated, TargetUser, IPAddress, ResultReason, CorrelationId;
let KnownIPs = SigninLogs
| where TimeGenerated between (ago(lookback) .. ago(window))
| where ResultType == "0"
| summarize by TargetUser = tolower(UserPrincipalName), IPAddress;
Registrations
| join kind=leftanti KnownIPs on TargetUser, IPAddress
| order by TimeGenerated desc
```

The [SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) table holds interactive sign-ins. A brand-new user with no history will always show up in the results, so the query works better as a review queue than as an automatic alert. Accounts created in the last few days can be handled separately.

<!-- Alessandro: query not run in a real environment. Validate the result volume and whether it is worth also checking AADNonInteractiveUserSignInLogs before turning it into a scheduled rule. -->

## How to respond to a suspicious registration

The page [Manage user authentication methods for Microsoft Entra multifactor authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userdevicesettings) describes the actions available to administrators:

1. **Revoke sessions** invalidates the user's refresh tokens and forces reauthentication across active sessions and applications.
2. **Require re-register MFA** deactivates the user's hardware OATH tokens and deletes phone numbers, Microsoft Authenticator apps and software OATH tokens, forcing a new registration.
3. Methods can also be reviewed and removed one by one, including with Microsoft Graph PowerShell, using cmdlets such as `Get-MgUserAuthenticationPhoneMethod` and `Remove-MgUserAuthenticationPhoneMethod` for phone methods.

The same page states that the Authentication Administrator role can require other users to reset their password, re-register for MFA or have their sessions revoked.

In practice, order matters: if the password is changed and the attacker's method stays registered, they can sign in again. Remove the suspicious method, revoke sessions, and only then hand the account back to the user through a controlled registration process.

<!-- Alessandro: add here the response runbook you use for compromised account incidents, if you have one. -->

## Prevention: protect registration itself

Entra ID lets you treat method registration as a protected action. The guide [Protect security info registration with Conditional Access policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration) uses the **Register security information** user action in a policy that requires MFA from anyone outside a trusted network. The main steps:

1. Under **Users**, include **All users** and exclude guest and external users, plus emergency access accounts.
2. Under **Target resources**, select **User actions** and check **Register security information**.
3. Under **Conditions > Locations**, include **Any location** and exclude **All trusted locations**.
4. Under **Grant**, use **Require authentication strength**.
5. Start in **Report-only** and enable it afterwards.

The guide carries two warnings. First, external authentication methods are currently incompatible with authentication strength. Second, starting July 6, 2026, policies that target Register security information also apply during Windows Hello for Business and macOS Platform SSO credential registration.

### What about users who have no MFA yet?

This is where the [Temporary Access Pass (TAP)](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass) comes in. According to the documentation, a TAP is a time-limited passcode for single or multiple sign-ins, and its most common use is registering authentication details during the first sign-in or device setup. The Conditional Access guide confirms that TAP satisfies the policy's MFA requirement. That way the first registration no longer depends on the password alone: IT delivers the TAP through a trusted channel, with a short lifetime, and the user registers the method. The documentation allows lifetimes between 10 minutes and 30 days, with a default of 1 hour. TAP does not work for guest users, which is why they are excluded from the policy.

<!-- Alessandro: add here how TAP delivery for new employees works, or would work, in the environments you administer, without identifying the companies. -->

## Conclusion

Registering an MFA method is a small event in the audit log, but it can be the moment an attacker turns a leaked password into lasting access. Three measures cover most of the risk: review "security info" events with the queries above, protect the Register security information action with Conditional Access, and use TAP so the first registration does not depend on the password alone. During response, remove the suspicious method and revoke sessions before considering the account clean.

## References

- MITRE ATT&CK. [Account Manipulation: Device Registration (T1098.005)](https://attack.mitre.org/techniques/T1098/005/)
- Microsoft Learn. [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [Manage user authentication methods for Microsoft Entra multifactor authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userdevicesettings)
- Microsoft Learn. [Protect security info registration with Conditional Access policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration)
- Microsoft Learn. [Configure Temporary Access Pass to register passwordless authentication methods](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
