---
title: "Windows LAPS with Intune and Entra ID: a unique local admin password on every machine"
date: 2026-11-18
draft: false
description: "How to enable Windows LAPS in Microsoft Entra ID, configure the policy in Intune, control who can read the local administrator password and monitor password recoveries with KQL in Microsoft Sentinel."
summary: "Step by step to enable Windows LAPS with Intune and Entra ID, control who reads the local administrator password and monitor recoveries with KQL."
categories: ["Endpoint"]
tags: ["intune", "entra id", "windows laps", "kql", "sentinel", "privileged accounts"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0004", tecnica: "T1078.003", nome: "Local Accounts" }
  - { tatica: "TA0008", tecnica: "T1550.002", nome: "Pass the Hash" }
---

In many environments, the local administrator account on every workstation shares the same password, set in the system image years ago. Compromising one machine is enough to get administrative access to the others. MITRE ATT&CK describes this abuse in [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/): password reuse may allow the abuse of local accounts across a set of machines for privilege escalation and lateral movement.

The same page lists two direct mitigations. M1027 asks for complex, unique passwords for local administrator accounts across all systems on the network, and M1026 states that implementing LAPS helps prevent reuse of those credentials. In [Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/), the guidance is to limit credential overlap across systems to reduce lateral movement.

This article shows how to do that with Windows LAPS, Microsoft Intune and Microsoft Entra ID, and how to keep track of who looks up the passwords.

## What Windows LAPS is

Windows LAPS rotates and backs up the password of a local administrator account on each device. According to the [Microsoft overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview), it is a native Windows implementation, separate from the older product, and it does not require installing legacy Microsoft LAPS. Legacy LAPS is deprecated as of Windows 11 23H2, and newer versions block installation of the old MSI package. Entra ID and Intune support has been generally available since October 23, 2023.

Compatibility points worth checking before you start:

- **Operating systems:** Windows 11 23H2 and later, plus earlier Windows 11 versions, Windows 10, Windows Server 2022 and 2019 with the April 11, 2023 update or later. The page notes that Windows 10 reached end of support on October 14, 2025.
- **Join type:** the [Entra documentation](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords) states that LAPS with Entra backup works only on Microsoft Entra joined or Microsoft Entra hybrid joined devices. Registered-only devices are not supported.

## Step 1: enable LAPS in Entra ID

With at least the Cloud Device Administrator role, go to **Entra ID > Devices > Overview > Device settings**, select **Yes** for **Enable Local Administrator Password Solution (LAPS)** and save. The [Intune policy](https://learn.microsoft.com/en-us/intune/device-security/laps/deploy-policy) depends on this setting, and the documentation asks you to make sure LAPS is enabled in Entra before deploying it.

## Step 2: create the policy in Intune

In the Intune admin center, go to **Endpoint security > Account protection > Create Policy**, pick the **Windows** platform and the **Local admin password solution (Windows LAPS)** profile. Microsoft recommends assigning the policy to device groups and avoiding conflicting policies, which can fail to process. Settings from the LAPS CSP take precedence over GPOs and legacy LAPS.

The main settings, with values from the [policy reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings):

| Setting | What it does | Default |
|---|---|---|
| BackupDirectory | Backup target: 0 disabled, 1 Entra ID, 2 Active Directory | 0 (disabled) |
| AdministratorAccountName | Managed account; empty manages the built-in administrator. LAPS does not create the account | Built-in administrator |
| PasswordAgeDays | Maximum password age; with Entra backup the minimum is 7 days | 30 |
| PasswordComplexity | Password composition (4 = upper case, lower case, numbers and special characters) | 4 |
| PasswordLength | Length, from 8 to 64 | 14 |
| PostAuthenticationActions | Action after the account is used (1 reset; 3 reset and sign out; 5 reset and reboot) | 3 |
| PostAuthenticationResetDelay | Hours until that action runs, from 0 to 24 | 24 |

The most overlooked one is `BackupDirectory`: the default is disabled, so the policy only takes effect when you choose Entra ID. If you choose Active Directory on a device that is not domain joined, Intune applies the policy without error, but LAPS cannot back up the account.

Post-authentication actions limit the lifetime of a password that has been seen: after someone uses the account, LAPS changes the password at the end of the delay. Lowering `PostAuthenticationResetDelay` to a few hours is my own choice for teams that use the account in short support sessions, not an official value.

On Windows 11 24H2 and Windows Server 2025, LAPS can also manage the account automatically, creating its own account (default prefix `WLapsAdmin`) and, if configured, adding a random six-digit suffix to the name at each rotation.

<!-- Alessandro: add your experience with the configuration used in the environments you manage, without naming companies. -->

## Step 3: decide who can read the password

Reading the password requires the `microsoft.directory/deviceLocalCredentials/password/read` permission. Among built-in roles, the Entra documentation lists Cloud Device Administrator and Intune Administrator. Helpdesk Administrator, Security Administrator and Security Reader see only the metadata, not the password.

To narrow the scope:

- **Custom role:** with Entra ID P1 or P2, you can create a role with only the password read permission.
- **Administrative units:** the Cloud Device Administrator role can be assigned scoped to an administrative unit that holds only one team's devices.
- **Conditional Access:** policies targeting the built-in roles, such as requiring MFA for administrators, protect password recovery. The same page says custom roles and administrative unit-scoped roles are not supported for this targeting.

One detail for the response plan: there is no way to recover the password of a deleted device in Entra ID.

## Step 4: view and rotate the password

In Intune, the password is shown under **Devices > All devices >** device **> Monitor > Local admin password**, with the last and next rotation dates. Viewing the password triggers an audit event. The **Rotate Local admin password** action forces a change, with documented limits: the device must have completed at least one backup, an Entra joined device must be online, and the action is not available as a bulk action. In Entra, each recovery and each update shows up in the audit log as the `Recover device local administrator password` and `Update device local administrator password` activities.

## Monitor recoveries with KQL

Someone who reads many passwords in a short time may be preparing lateral movement, whether it is a rushed operator or a compromised privileged account. With Entra audit logs sent to Microsoft Sentinel, the query below summarizes recoveries by who performed them:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Recover device local administrator password"
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| mv-expand Target = TargetResources
| extend Device = tostring(Target.displayName)
| summarize Recoveries = count(), Devices = dcount(Device), DeviceList = make_set(Device, 50),
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Actor, Result
| order by Devices desc
```

The `OperationName`, `InitiatedBy`, `TargetResources` and `Result` columns are in the [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs). The inner fields of `InitiatedBy` and `TargetResources` need to be checked in your own logs. To turn it into a scheduled rule, my starting point is to alert when the same person recovers passwords for more than five devices in one hour; tune it to your support volume.

<!-- Alessandro: query not run in a real environment. Validate the activity name, the TargetResources and InitiatedBy fields and the alert threshold before publishing it as a rule. -->

## Conclusion

Windows LAPS solves an old problem with little effort: enable it in Entra, one Intune policy with backup to Entra ID and a clear decision about who can read the passwords. The auditing that comes with it turns every password read into an event that can be reviewed and, with KQL, into an alert.

## References

- Microsoft Learn. [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- Microsoft Learn. [Windows Local Administrator Password Solution in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords)
- Microsoft Learn. [Manage Windows LAPS policy with Microsoft Intune](https://learn.microsoft.com/en-us/intune/device-security/laps/deploy-policy)
- Microsoft Learn. [Monitoring Windows LAPS in Intune](https://learn.microsoft.com/en-us/intune/device-security/laps/monitor)
- Microsoft Learn. [Configure policy settings for Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- MITRE ATT&CK. [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/)
- MITRE ATT&CK. [Use Alternate Authentication Material: Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)
