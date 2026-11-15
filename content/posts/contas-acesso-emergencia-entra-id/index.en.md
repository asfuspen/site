---
title: "Emergency access accounts in Entra ID: configuration, monitoring and testing"
date: 2026-11-15
draft: false
description: "Microsoft best practices for emergency access (break-glass) accounts in Microsoft Entra ID: how many to create, how to authenticate under mandatory MFA, Conditional Access exclusion, KQL usage alerts and a testing routine."
summary: "How to configure, monitor and test emergency access accounts in Entra ID following Microsoft documentation, with KQL queries that alert on usage and changes."
categories: ["Identity"]
tags: ["entra id", "conditional access", "kql", "sentinel", "privileged accounts"]
series: ["KQL detections"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0001", tecnica: "T1078.004", nome: "Cloud Accounts" }
  - { tatica: "TA0003", tecnica: "T1078.004", nome: "Cloud Accounts" }
---

Every organization that runs on Microsoft Entra ID depends on someone being able to sign in as an administrator. When the federated identity provider goes down, when the administrators' only MFA method stops working, or when a misconfigured Conditional Access policy locks everyone out, the way back in is an emergency access account, also known as a break-glass account.

The catch is that this account holds the most powerful role in the tenant and is almost never used. For an attacker, it is a valuable target: MITRE ATT&CK describes the abuse of legitimate cloud accounts in [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/), associated with initial access, persistence, privilege escalation and stealth. This article summarizes the recommendations from [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access) and shows how to turn any use of these accounts into an alert.

## When you need the emergency account

The documentation lists situations in which an organization can lose administrative access:

- User accounts are federated and federation becomes unavailable, because of a cell network break or an identity provider outage.
- Administrators registered MFA only on methods that stopped working, such as phone calls or text messages.
- The last person with Global Administrator left the organization, or the account was deleted or disabled on-premises.
- A natural disaster takes down mobile networks.
- All Global Administrator and Privileged Role Administrator assignments are eligible in PIM, require approval, and there are no approvers. The page states that this effectively locks tenant administration.

## How to configure

Microsoft's main recommendations are:

1. **At least two accounts**, for redundancy.
2. **Cloud-only accounts** on the `*.onmicrosoft.com` domain, not federated and not synchronized from on-premises Active Directory. Emergency access for the cloud and for on-premises systems should be independent of each other.
3. **Permanently active Global Administrator.** In Privileged Identity Management, the assignment should be active permanent, not eligible. An account that has to activate its role depends on exactly the processes that may be broken during the emergency.
4. **Not tied to a person.** The account should not be associated with a specific user or with personal devices, such as an employee's phone.
5. **Authentication different from the other administrators'**, for example a FIDO2 security key used only by the emergency accounts. The credential or device must not expire or be removed by automated cleanup of unused items.
6. **Securely stored credentials**, known only to authorized people, kept in fireproof safes in separate locations. Use should start from a secure workstation, such as a Privileged Access Workstation.

<!-- Alessandro: add your experience with storing FIDO2 keys or with custody processes at customers here. -->

## Mandatory MFA applies to them too

Many organizations kept emergency accounts with only a long password to avoid any dependency on MFA. That model no longer works. The page on [mandatory MFA for Azure and admin portals](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication) says emergency accounts are also required to sign in with MFA once enforcement begins, and that the rule applies to all accounts, break-glass included. The first phase covers the Azure portal, the Entra admin center and the Intune admin center since October 2024, and the Microsoft 365 admin center since February 2025.

For these accounts, Microsoft recommends two passwordless methods that satisfy the requirement:

- **Passkey (FIDO2)**, the recommended option.
- **Certificate-based authentication**, if the organization already has a public key infrastructure.

## Conditional Access: exclude, but deliberately

The emergency account should be excluded from every Conditional Access policy that blocks or restricts sign-in. The documentation explains why: if it is subject to MFA, compliant device or similar requirements, it may be unusable in exactly the emergency it exists for. Report-only policies don't block access and don't need an exclusion.

In practice, the suggestion is to create a dedicated group, such as `EmergencyAccess`, and exclude it from blocking or restricting policies. The same page recommends testing, for example every quarter, that the accounts can still sign in with the current Conditional Access configuration, and keeping contingency policies ready to enable during an outage.

## Monitoring: every use becomes an alert

Since the account is almost never used, any sign-in is an event that needs an explanation. The documentation says to send Entra sign-in logs to Azure Monitor and create a custom log search alert rule on the `SigninLogs` table, filtering by each account's Object ID, with a static "greater than 0" threshold and severity 0 (critical). The official example uses only `SigninLogs`. The version below is my own adaptation that also covers non-interactive sign-ins and shows which table each row came from:

```kql
let BreakGlassIds = dynamic(["00aa00aa-bb11-cc22-dd33-44ee44ee44ee", "11bb11bb-cc22-dd33-ee44-55ff55ff55ff"]);
union withsource = SourceTable SigninLogs, AADNonInteractiveUserSignInLogs
| where UserId in (BreakGlassIds)
| project TimeGenerated, SourceTable, UserPrincipalName, UserId, AppDisplayName, IPAddress, ResultType
| order by TimeGenerated desc
```

Replace the sample identifiers with your accounts' Object IDs, shown under **Entra ID > Users**. Filtering by Object ID rather than UPN keeps the alert working if the account is renamed. Keep failed attempts in scope: a wrong password on an emergency account deserves investigation too. The same query works as a scheduled analytics rule in Microsoft Sentinel, which the documentation mentions as an alternative to Azure Monitor.

Beyond sign-ins, it is worth knowing when someone changes these accounts: a new authentication method, role removal, password reset or deletion. The next query looks for audit log events that target one of the accounts:

```kql
let BreakGlassIds = dynamic(["00aa00aa-bb11-cc22-dd33-44ee44ee44ee", "11bb11bb-cc22-dd33-ee44-55ff55ff55ff"]);
AuditLogs
| where TimeGenerated > ago(1d)
| mv-expand Target = TargetResources
| where tostring(Target.id) in (BreakGlassIds)
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, Category, Result, Actor, TargetUpn = tostring(Target.userPrincipalName)
| order by TimeGenerated desc
```

The `TargetResources` and `InitiatedBy` columns are dynamic, and the inner fields used here (`id`, `userPrincipalName`, `displayName`) need to be checked against your own logs. The one-day window is my own starting point, not an official value.

<!-- Alessandro: queries not run in a real environment. Validate the inner fields of TargetResources and InitiatedBy and the alert volume before turning them into scheduled rules. -->

When the alert fires, Microsoft recommends preserving Entra and workload logs, checking whether the use was a planned test, a real emergency or misuse, and reviewing the actions taken with the account.

## Test before you need it

An emergency account that was never tested is a gamble. The documentation asks for validation at least every 90 days, whenever IT staff change, and when the organization's Entra subscriptions change. The minimum routine includes:

- Letting the security monitoring team know the test is happening.
- Reviewing the list of authorized people and keeping the process documented.
- Training administrators and security officers on the procedure.
- Confirming that the accounts can sign in and perform administrative tasks.
- Checking that nobody registered MFA or password reset on a personal device or personal details.
- Changing safe combinations periodically and whenever someone with access leaves the organization.

<!-- Alessandro: add how you run the quarterly test and who takes part here. -->

## Conclusion

The emergency account has to be available when everything else fails and, at the same time, be the most closely watched account in the tenant. That means two cloud-only accounts, permanently active Global Administrator, a FIDO2 passkey or certificate to meet mandatory MFA, a deliberate Conditional Access exclusion, a critical alert on any sign-in, and a test every 90 days. The sign-in query from this article is also in the site's [KQL library]({{< relref "/kql" >}}).

## References

- Microsoft Learn. [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- Microsoft Learn. [Planning for mandatory multifactor authentication for Azure and other admin portals](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication)
- MITRE ATT&CK. [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [AADNonInteractiveUserSignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
