---
title: "Illicit consent grants in Entra ID: detect, remove and prevent"
date: 2026-11-16
draft: false
description: "How the illicit consent grant attack on OAuth apps works, why a password reset does not fix it, how to find the grants in Sentinel with KQL, how to remove them and how to restrict user consent in Entra ID."
summary: "The illicit consent grant attack, why a password reset does not fix it, a KQL query for Sentinel, removing the grants and the setting that restricts user consent."
categories: ["Identity"]
tags: ["entra id", "sentinel", "kql", "oauth", "applications"]
series: ["KQL detections"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0006", tecnica: "T1528", nome: "Steal Application Access Token" }
---

Not every phishing attack asks for a password. In an illicit consent grant attack, the attacker asks for something else: that the victim authorize an application to access their data. The [Microsoft Defender for Office 365 documentation](<https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants>) describes the playbook: the attacker creates a registered application in Microsoft Entra ID and tricks the user into granting that application consent. From then on, the application has account-level access to the data without needing an organizational account.

The detail that changes incident response is on the same page: password resets and MFA aren't effective against this type of attack. Access doesn't depend on the victim's password, but on the grant they approved.

MITRE ATT&CK records this behavior as [Steal Application Access Token (T1528)](<https://attack.mitre.org/techniques/T1528/>), under the Credential Access tactic (TA0006). The technique describes an adversary who builds a malicious application to gain access to resources with the user's OAuth token and sends a spearphishing link so the victim grants that access.

## Why users can grant it

The starting point is the default setting. According to [Configure how users consent to applications](<https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent>), by default all users are allowed to consent to applications for permissions that don't require administrator consent. In a tenant that never reviewed this setting, any user can authorize an unknown application to read their data.

There are two levels of consent, and the difference matters during triage. The detection page says to check the `IsAdminConsent` field: when it is `True`, whoever consented might have granted broad access to data. Another indicator is a `ConsentType` of `AllPrincipals`, which means a grant that applies to every user in the tenant, not only to whoever clicked.

<!-- Alessandro: add here whether you have reviewed the user consent setting in the environments you manage and what you found, without data that identifies the environment. -->

## What to look for

The same page lists the signs of a suspicious grant:

- **"Consent to application" activity** in the Microsoft Purview audit log. The page warns that the entry can take 30 minutes to 24 hours to show up.
- **`ConsentType` set to `AllPrincipals`**, meaning consent for the whole organization.
- **Permissions containing "Read", "Write" or "All"**, which indicate read or write access to data.
- **High-value users** among those who consented.
- **Odd application names**: misspelled, overly bland or hacker-sounding names.

## The query in Sentinel

In Microsoft Sentinel, Entra ID audit events land in the [`AuditLogs`](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs>) table, which has the `OperationName`, `InitiatedBy`, `TargetResources`, `Result` and `CorrelationId` columns used below.

The way to extract the user, IP, application and consent type comes from the official [Rare application consent](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml>) rule in the Azure-Sentinel repository. The query below is a simplified hunting version: it lists every consent in the last seven days and flags the ones that apply to the whole tenant.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Consent to application"
| extend InitiatedByUser = iff(isnotempty(tostring(InitiatedBy.user.userPrincipalName)),
    tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend IpAddress = tostring(InitiatedBy.user.ipAddress)
| mv-apply TargetResource = TargetResources on (
    where TargetResource.type =~ "ServicePrincipal"
    | extend AppName = tostring(TargetResource.displayName),
             Props = tostring(TargetResource.modifiedProperties)
  )
| parse Props with * "ConsentType: " ConsentType "]" *
| extend TenantWide = Props has "AllPrincipals"
| project TimeGenerated, InitiatedByUser, IpAddress, AppName, ConsentType, TenantWide, Result, CorrelationId
| order by TimeGenerated desc
```

<!-- Alessandro: run the query in your workspace before approving. Check that the ConsentType parse returns a clean value and note here which modifiedProperties field holds the granted permissions, for a future version that filters by scope. -->

During triage, start with the rows where `TenantWide` is true and with applications you don't recognize. Then open the application under **Enterprise applications > Permissions** to see the granted permissions.

To turn the hunt into an alert, the Rare application consent rule already compares against history: it alerts when a user who never consented, or an application that never received consent, shows up in the current period. It's worth enabling it from the content hub before writing your own rule.

## How to remove the grant

The [Review permissions granted to enterprise applications](<https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions>) page has an important caveat: in the portal, under **Enterprise applications > the app > Permissions**, you can only revoke grants made by an administrator. Grants made by users must be removed through the API or PowerShell.

In Microsoft Graph PowerShell, the page uses `Get-MgOauth2PermissionGrant` to list delegated permissions and `Remove-MgOauth2PermissionGrant` to remove them:

```powershell
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<grant-id>"
```

For application permissions, the cmdlets are `Get-MgServicePrincipalAppRoleAssignment` and `Remove-MgServicePrincipalAppRoleAssignedTo`. Follow the page for the parameters of each case.

The detection page adds a short-term measure: block sign-in for the affected account while the investigation runs.

Removing the grant isn't enough on its own. The same Entra page warns that revoking the current permission doesn't stop users from consenting again. That requires changing the consent setting.

<!-- Alessandro: add your response playbook here, for example who you notify and how you confirm the application did not access data after removal. -->

## Prevention

The consent settings page offers two built-in Microsoft policies:

| Policy ID | What it allows |
|---|---|
| `microsoft-user-default-low` | User consent for apps from verified publishers, for selected permissions |
| `microsoft-user-default-legacy` | User consent for apps |

You can also disallow user consent. In PowerShell, the setting is changed with `Update-MgPolicyAuthorizationPolicy`, after connecting with `Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"`. One caution: the page's PowerShell example repeats the `managePermissionGrantsForSelf` prefix in the policy ID, while the Graph example uses `managePermissionGrantsForSelf.microsoft-user-default-low`. Check the value before applying it.

The change only affects future consent operations. Existing grants stay active, so the review with the query above should go along with it.

Once consent is restricted, the [admin consent workflow](<https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow>) comes in: when a user tries to access an application and can't consent, they send an approval request, which reaches the designated reviewers by email. This keeps the restriction from becoming a dead end for someone who needs a legitimate application.

Finally, the detection page recommends reviewing consent grants every week and using Microsoft Defender for Cloud Apps OAuth app policies.

## Conclusion

Illicit consent abuses a legitimate feature and doesn't depend on the password, so the classic response of resetting credentials doesn't remove the access. The defense has three parts: restrict user consent to verified publishers and selected permissions, with the approval workflow for legitimate requests; monitor "Consent to application" activity in Sentinel; and, during an incident, remove the grant with PowerShell, because the portal doesn't revoke what the user granted.

## References

- Microsoft Learn. [Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
- Microsoft Learn. [Configure how users consent to applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- Microsoft Learn. [Configure the admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow)
- Microsoft Learn. [Review permissions granted to enterprise applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- Azure-Sentinel (GitHub). [Rare application consent](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml)
- MITRE ATT&CK. [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/)
