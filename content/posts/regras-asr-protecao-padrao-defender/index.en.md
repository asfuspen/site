---
title: "Standard protection ASR rules: from audit mode to block in Defender for Endpoint"
date: 2026-11-14
draft: false
description: "How to turn on the three attack surface reduction (ASR) rules Microsoft classifies as standard protection, test the rest in audit mode and track the events with KQL in Defender XDR."
summary: "The three standard protection ASR rules, how to test the others in audit mode and how to measure impact with KQL in Defender XDR before blocking."
categories: ["Endpoint"]
tags: ["defender for endpoint", "defender xdr", "asr", "kql", "powershell", "hardening"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0006", tecnica: "T1003.001", nome: "LSASS Memory" }
  - { tatica: "TA0003", tecnica: "T1546.003", nome: "Windows Management Instrumentation Event Subscription" }
---

Microsoft Defender for Endpoint's attack surface reduction (ASR) rules block behaviors that malware and attackers rely on: an Office document that launches a child process, an obfuscated script, a process trying to read LSASS memory. The catch is that some of these behaviors can also show up in legitimate software, such as macros, management tools and in-house installers. Turning everything on in block mode at once risks breaking those applications.

Microsoft itself proposes a safer path: turn on the low-risk rules right away and test the rest in audit mode before blocking. This article walks through that path with the cmdlets and the query from the official documentation.

## Prerequisites

According to the [ASR rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview), the rules work on Pro and Enterprise editions of Windows 10 or later, Windows Server 2012 R2 or later and Azure Local 23H2 or later. Microsoft Defender Antivirus must be the active antivirus, with real-time protection and cloud-delivered protection on; Defender can't be in passive mode or off.

On licensing, the page says the rules don't require Microsoft 365 E5, but that advanced management capabilities, such as monitoring, reporting and configuration in the Defender XDR portal, aren't available with other licenses, citing Windows Pro and Microsoft 365 E3 as examples.

## Rule modes

Each rule is configured by GUID and given a mode. The [Enable attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure) page lists the values accepted by the `AttackSurfaceReductionRules_Actions` parameter:

| Value | Name | Effect |
| --- | --- | --- |
| `0` | `Disabled` | Rule off |
| `1` | `Enabled` | Block |
| `2` | `AuditMode` | Only logs the event |
| `5` | `NotConfigured` | Not configured |
| `6` | `Warn` | Blocks, but the user can unblock |

In Warn mode, the rule acts as if in block mode, but the user can select **Unblock** in the notification and allow the action for 24 hours. The overview says this mode requires Windows 10 1809 or later, isn't available in Configuration Manager and isn't supported by two rules: the LSASS credential theft rule and the rule that stops Office applications from injecting code into other processes.

## Step 1: turn on the standard protection rules

The [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) groups three rules under the "Standard protection rules" heading. The [deployment test guide](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test) says these rules can typically be enabled in block or Warn mode without testing.

| Rule | GUID |
| --- | --- |
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block credential stealing from the Windows local security authority subsystem | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |

Two details from the reference help clarify their scope. The driver rule stops applications from saving vulnerable signed drivers on the computer, but doesn't stop drivers already there from loading. The LSASS rule, which protects against credential theft from the process memory (MITRE ATT&CK technique [T1003.001](https://attack.mitre.org/techniques/T1003/001/)), isn't required when LSA protection is already enabled. The WMI rule covers persistence through WMI event subscriptions, technique [T1546.003](https://attack.mitre.org/techniques/T1546/003/).

On a test machine, PowerShell applies the three rules in block mode without removing the others:

```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled
```

The documentation makes two important points. First, `Set-MpPreference` overwrites every rule already configured, while `Add-MpPreference` and `Remove-MpPreference` only touch the rules you pass. Second, local settings have the lowest precedence: any policy applied through Intune, Configuration Manager or Group Policy overwrites them at startup. In production, then, configuration should come from the management tool you already use; PowerShell is for the lab and for checking.

To see what is applied on a device, the page provides this command:

```powershell
$p = Get-MpPreference;0..([math]::Min($p.AttackSurfaceReductionRules_Ids.Count,$p.AttackSurfaceReductionRules_Actions.Count)-1) | % {[pscustomobject]@{Id=$p.AttackSurfaceReductionRules_Ids[$_];Action=$p.AttackSurfaceReductionRules_Actions[$_]}} | Format-Table -AutoSize
```

A word of caution when copying examples: in the `Set-MpPreference` example on the configuration page, the WMI rule's GUID is missing its last character (`...636979351e5`). The full GUID, as in the reference, ends in `351e5b`.

## Step 2: audit the other rules on a pilot group

For the remaining rules, the test guide recommends starting with a small initial ring of devices and typically enabling all rules in audit mode at the same time. The guide's steps are: test in audit mode, review the data and assess impact, then configure the exclusions you need.

<!-- Alessandro: add your experience here with pilot group size and how long you usually keep rules in audit mode. -->

## Step 3: measure impact with KQL

In audit mode nothing is blocked, but every occurrence becomes an event. The rules overview gives the starting query for Defender XDR advanced hunting:

```kql
DeviceEvents
| where ActionType startswith "Asr"
| where ActionType endswith "Audited"
```

To decide rule by rule, it helps more to group by rule and by the process that triggered the event. The columns below are listed in the [DeviceEvents table schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table):

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Asr" and ActionType endswith "Audited"
| summarize Events = count(), Devices = dcount(DeviceName),
    SampleFiles = make_set(FileName, 5), SampleFolders = make_set(FolderPath, 5)
    by ActionType, InitiatingProcessFileName
| order by Events desc
```

<!-- Alessandro: query not run in a real environment. Validate the output and adjust the window to your tenant's retention. -->

The 30-day window is my own starting point, not an official value. A rule with few events, all from processes you don't recognize, is a candidate for blocking. A rule that fires hundreds of times from a business application needs an exclusion, or a conversation with the application owner, first. Outside the portal, the test guide points to event 1122 in the **Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational** log for rules in audit mode.

The same queries work after blocking: just swap `Audited` for `Blocked`. For the LSASS rule, for example, the reference lists the action types `AsrLsassCredentialTheftAudited` and `AsrLsassCredentialTheftBlocked`.

## Step 4: exclusions with care

When a legitimate application triggers a rule, a path exclusion is set with `AttackSurfaceReductionOnlyExclusions`. Following the documented syntax:

```powershell
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Data\LOBApp\app1.exe"
```

As practical advice, not a documented rule, prefer the executable's path over a whole folder and record the reason for each exclusion: anything excluded is no longer evaluated by the ASR rules. To check the exclusions in place, use `(Get-MpPreference).AttackSurfaceReductionOnlyExclusions`.

## Conclusion

The three standard protection rules address LSASS credential theft, WMI persistence and vulnerable driver abuse, and Microsoft says they can typically go to block mode without prior testing. The rest calls for method: audit on a pilot group, event analysis with KQL, targeted exclusions and blocking in rings. This article's impact query is also in the site's [KQL library]({{< relref "/kql" >}}).

## References

- Microsoft Learn. [Attack surface reduction rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- Microsoft Learn. [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- Microsoft Learn. [Test attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test)
- Microsoft Learn. [Enable attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)
- Microsoft Learn. [DeviceEvents table in the advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- MITRE ATT&CK. [OS Credential Dumping: LSASS Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001/)
- MITRE ATT&CK. [Event Triggered Execution: Windows Management Instrumentation Event Subscription (T1546.003)](https://attack.mitre.org/techniques/T1546/003/)
