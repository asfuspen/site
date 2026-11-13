---
title: "Email forwarding rules: detection, triage and response in Exchange Online"
date: 2026-11-12
draft: false
description: "How attackers use inbox rules to divert and hide email after compromising an account, and how to detect it, turn it into a Sentinel rule, investigate and respond."
summary: "How attackers use inbox rules to divert and hide email, and how to detect it, turn it into a Sentinel rule, investigate and respond."
categories: ["Detection"]
tags: ["kql", "sentinel", "defender xdr", "exchange online", "email"]
series: ["KQL detections"]
nivel: "avancado"
featured: true
mitre:
  - { tatica: "TA0009", tecnica: "T1114.003", nome: "Email Forwarding Rule" }
  - { tatica: "TA0005", tecnica: "T1564.008", nome: "Email Hiding Rules" }
---

After compromising an email account, the attacker needs two things: to keep reading the messages and to keep the victim from noticing. Inbox rules deliver both. MITRE ATT&CK describes the first use in [Email Forwarding Rule (T1114.003)](<https://attack.mitre.org/techniques/T1114/003/>) and the second in [Email Hiding Rules (T1564.008)](<https://attack.mitre.org/techniques/T1564/008/>).

What makes this technique dangerous is on the T1114.003 page: a forwarding rule can maintain persistent access to the victim's email even after compromised credentials are reset by administrators. Changing the password does not remove the rule.

This post covers the whole cycle: where the event shows up, two KQL detections for Microsoft Sentinel, the equivalent query in Defender XDR, how to turn the detection into a scheduled rule, triage, response and prevention.

## Three ways to forward

Microsoft's [alert classification guide for email forwarding](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-email-forwarding>) lists three automatic forwarding mechanisms:

| Mechanism | Who configures it | How it shows up |
|---|---|---|
| Inbox rule | The user, or anyone with access to the mailbox | `New-InboxRule`, `Set-InboxRule` and `UpdateInboxRules` operations |
| Mailbox SMTP forwarding | Administrator | `Set-Mailbox` with `ForwardingSmtpAddress` |
| Transport rule (ETR) | Administrator | `New-TransportRule` and `Set-TransportRule`, organization-wide |

A transport rule requires administrative privilege, but the impact is larger. ATT&CK records a case in which the LAPSUS$ group set a tenant-level transport rule to send all mail in and out of the targeted organization.

For inbox rules, the parameters that matter are in the [`New-InboxRule`](<https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboxrule>) documentation: `ForwardTo` forwards the message, `ForwardAsAttachmentTo` forwards it as an attachment and `RedirectTo` redirects it. The [compromised account response page](<https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account>) adds a detail about `RedirectTo`: messages are not delivered to the original mailbox.

## Where the event shows up

The Microsoft Purview [audit log activities list](<https://learn.microsoft.com/en-us/purview/audit-log-activities>) distinguishes three operations, and the difference changes the detection:

- `New-InboxRule`: rule created in Outlook on the web.
- `Set-InboxRule`: rule modified in Outlook on the web.
- `UpdateInboxRules`: rule created, modified or removed using the Outlook client.

A query that only looks for `New-InboxRule` does not see rules created from the Outlook client.

In Microsoft Sentinel, these events land in the [`OfficeActivity`](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity>) table. The columns used here are `Operation`, `OfficeWorkload`, `Parameters` (the name and value of all parameters used with the cmdlet), `UserId`, `ClientIP` and `ResultStatus`.

In Defender XDR, the table is [`CloudAppEvents`](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table>). It is populated by Microsoft Defender for Cloud Apps and only has data if the Microsoft 365 connector is enabled under Settings > Cloud apps > App connectors.

## Detection 1: forwarding outside the organization

The query below extracts the forwarding destination and keeps only those outside your domains. The technique of turning the `Parameters` column into properties comes from the official rule [Multiple users email forwarded to same destination](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Office_MailForwarding.yaml>), in the Azure-Sentinel repository.

```kql
let InternalDomains = dynamic(["contoso.com"]);
OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload =~ "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress")
| mv-apply Parameter = todynamic(Parameters) on (
    summarize Parsed = make_bag(bag_pack(tostring(Parameter.Name), Parameter.Value))
  )
| extend Destination = tolower(tostring(coalesce(
    Parsed.ForwardTo, Parsed.RedirectTo, Parsed.ForwardAsAttachmentTo, Parsed.ForwardingSmtpAddress)))
| extend Destination = trim_start(@"smtp:", Destination)
| where isnotempty(Destination)
| mv-expand Target = split(Destination, ";") to typeof(string)
| extend TargetDomain = tostring(split(Target, "@")[1])
| where TargetDomain !in (InternalDomains)
| project TimeGenerated, UserId, ClientIP, Operation, Target, Parameters
| order by TimeGenerated desc
```

What each part does:

- `InternalDomains` must hold your organization's domains. Microsoft's guide says to validate that the destination is not an internal address or a sub-domain that belongs to the company, and that is what the final filter does.
- `mv-apply` with `make_bag` converts the parameter list into an object, so that `ForwardTo`, `RedirectTo`, `ForwardAsAttachmentTo` or `ForwardingSmtpAddress` can be read by name.
- `trim_start(@"smtp:", ...)` removes the prefix that `ForwardingSmtpAddress` may carry. The official rule does the same.
- `mv-expand` splits rules with more than one recipient.

<!-- Alessandro: validate this query in your lab by creating a test rule to an external address, and add the result here with fictitious or anonymized data. -->

## Detection 2: rules that hide messages

The second family does not exfiltrate anything. It keeps the victim from seeing warnings. The T1564.008 page says malicious rules commonly filter on words such as `malware`, `suspicious`, `phish` and `hack` in subjects and bodies, and move or delete the messages.

```kql
let Keywords = dynamic(["phishing", "spam", "suspicious", "malicious", "hijacked", "helpdesk"]);
OfficeActivity
| where TimeGenerated > ago(7d)
| where OfficeWorkload =~ "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("DeleteMessage", "MoveToFolder", "MarkAsRead")
| extend HasFilter = Parameters has_any ("SubjectContainsWords", "BodyContainsWords", "SubjectOrBodyContainsWords")
| extend HasAlertKeyword = Parameters has_any (Keywords)
| where HasAlertKeyword or not(HasFilter)
| project TimeGenerated, UserId, ClientIP, Operation, HasFilter, HasAlertKeyword, Parameters
| order by TimeGenerated desc
```

The query returns two cases, the same ones the [inbox manipulation guide](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules>) treats as suspicious:

- Rules with alert words in the filter. The `Keywords` list is a subset of the one used in the official [Malicious Inbox Rule](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Malicious_Inbox_Rule.yaml>). Adapt it to your organization's language: if internal warnings are written in another language, add terms in that language.
- Rules with no filter at all. The guide states that deleting all incoming email without filtering by keyword is an indicator of malicious activity.

During triage, also look at the destination folder. Microsoft cites Notes, Junk Email and RSS Subscriptions as common destinations, and the combination of moving to a less noticeable folder and marking as read.

<!-- Alessandro: add here a case you have investigated or reproduced in a lab. -->

## The same hunt in Defender XDR

Those working in the Defender portal can use the query Microsoft itself publishes in the inbox manipulation guide. It includes `UpdateInboxRules`, so it covers the Outlook client:

```kql
let start_date = now(-10h);
let end_date = now();
let user_id = ""; // enter here the user id
CloudAppEvents
| where Timestamp between (start_date .. end_date)
| where AccountObjectId == user_id
| where Application == @"Microsoft Exchange Online"
| where ActionType in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule", "UpdateInboxRules") //set new inbox rule related operations
| project Timestamp, ActionType, CountryCode, City, ISP, IPAddress, RuleConfig = RawEventData.Parameters, RawEventData
```

Two notes before using it. The value of `user_id` is the account identifier in Entra ID, not the email address. And the table reference lists the internet provider column as `Isp`, while the published query writes `ISP`. If the query reports a missing column, that is the first place to look.

The guides also provide baseline queries that compare the account's activity by provider, country and user agent over the 30 or 60 days before the alert. They answer whether the rule was created from somewhere that user has never been.

## From query to scheduled rule

A query that only runs when someone remembers is not a detection. In Sentinel, the [scheduled analytics rule](<https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules>) has four decisions that deserve attention:

1. **Frequency and period.** "Run query every" sets how often the query runs and "Lookup data from the last" sets the period covered. Both accept 5 minutes to 14 days, and the period must be longer than or equal to the frequency. The two official rules cited run once a day: the forwarding rule looks back 7 days and the malicious rule one looks back 1 day.
2. **The time column.** The documentation asks for the query to return `TimeGenerated`, because the rule uses that column as the reference for the lookback period. Both queries above project it. When pasting into the rule, remove the `ago(7d)` filter from the query or align it with the configured period.
3. **Entity mapping.** It is what links the alert to the account and the IP in the incident. The official rules map `UserId` to the Account entity and the client IP to the IP entity. One caveat: both process `ClientIP` before mapping, because the value may include a port.
4. **Grouping.** By default, the rule generates a single alert per run. For this scenario, one alert per event makes it easier to treat each mailbox as a separate case.

<!-- Alessandro: add here the settings you use in production or in the lab, and the alert volume you observed. -->

## Triage: is it malicious?

The questions come from Microsoft's alert classification guides:

1. Is the destination external? An internal address or company sub-domain changes the analysis.
2. Does the rule have a filter? Words tied to security alerts deserve attention, and no filter at all is suspicious too.
3. Where was the rule created from? Compare IP, provider and country with the user's history.
4. Did other alerts trigger for the user before the rule was created?
5. Does the same IP show up in other suspicious activity in the tenant?
6. Does the same destination show up in more than one mailbox? That is exactly the pattern the official forwarding rule looks for.

## Response

The order below follows the [compromised account response page](<https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account>):

1. **Disable the account** until the investigation is complete. If that is not possible, reset the password. The page warns that app passwords are not automatically revoked on reset.
2. **Revoke active sessions**, which invalidates ongoing access with the stolen credentials.
3. **Review MFA devices** and remove any the attacker added.
4. **Review applications with user consent.**
5. **Review administrative roles** assigned to the account.
6. **Review mail forwarders** and remove the suspicious ones.

For step 6, the page provides two commands. The first shows the forwarding configured on the mailbox. A nonblank value in `ForwardingSmtpAddress` means email is being forwarded to an external recipient.

```powershell
Get-Mailbox -Identity <Identity> | Format-List Forwarding*Address,DeliverTo*
```

The second lists the rules, including hidden ones:

```powershell
Get-InboxRule -Mailbox <Identity> -IncludeHidden | Format-List Name,Enabled,RedirectTo,Forward*,Identity
```

`-IncludeHidden` is not a detail. ATT&CK describes adversaries using MAPI to modify the rule properties and make it invisible in Outlook, Outlook on the web and most Exchange administration tools.

## Prevention

The most direct control is in the [outbound spam policy](<https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding>), which has three values for automatic external forwarding:

- **Automatic - System-controlled:** the default. The page explains that the behavior can differ by organization and recommends configuring an explicit value.
- **On:** automatic external forwarding is allowed.
- **Off:** automatic external forwarding is disabled, and the sender gets a non-delivery report.

With Off, inbox rules and mailbox forwarding that redirect to external addresses stop working. Forwarding between internal users is not affected. The blocked message comes back with code `5.7.520`.

ATT&CK lists the same measure as mitigation M1042, alongside regular auditing of rules (M1047).

## What this post does not cover

- **Rules created by the Outlook client in Sentinel.** The two `OfficeActivity` queries filter `New-InboxRule`, `Set-InboxRule` and `Set-Mailbox`. `UpdateInboxRules` operations are left out and need their own handling.
- **Transport rules.** Detecting `New-TransportRule` and `Set-TransportRule` deserves a separate post.
- **Built-in Defender for Cloud Apps detections.** The [anomaly detection policies page](<https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy>) says the legacy suspicious forwarding and inbox manipulation policies were disabled and migrated to a new model. Check what is active in your tenant before relying on them.
- **Validation in a real environment.** Queries 1 and 2 were written from the documentation and the official rules, and have not yet been run in a tenant.

## Conclusion

An inbox rule is cheap persistence: it survives a password change, can be hidden and uses a legitimate feature. The defense has three layers. Prevention turns off automatic external forwarding. Detection follows rule creation and changes, with attention to external destinations and to rules that delete or move messages. Response removes the rule together with the credential reset, never the password alone.

The previous post in the series covers [password spray]({{< relref "/posts/password-spray-kql-sentinel" >}}), one of the ways to reach the account that later receives these rules.

## References

- MITRE ATT&CK. [Email Collection: Email Forwarding Rule (T1114.003)](<https://attack.mitre.org/techniques/T1114/003/>)
- MITRE ATT&CK. [Hide Artifacts: Email Hiding Rules (T1564.008)](<https://attack.mitre.org/techniques/T1564/008/>)
- Microsoft Learn. [Alert classification for suspicious inbox forwarding rules](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-forwarding-rules>)
- Microsoft Learn. [Alert classification for suspicious inbox manipulation rules](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules>)
- Microsoft Learn. [Alert classification for suspicious email forwarding activity](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-email-forwarding>)
- Microsoft Learn. [Respond to a compromised cloud email account](<https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account>)
- Microsoft Learn. [Control automatic external email forwarding](<https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding>)
- Microsoft Learn. [New-InboxRule](<https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboxrule>)
- Microsoft Learn. [OfficeActivity table reference](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity>)
- Microsoft Learn. [CloudAppEvents table](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table>)
- Microsoft Learn. [Create scheduled analytics rules](<https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules>)
- Microsoft Learn. [Audit log activities](<https://learn.microsoft.com/en-us/purview/audit-log-activities>)
- Microsoft Learn. [Anomaly detection policies in Defender for Cloud Apps](<https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy>)
- Azure-Sentinel. [Multiple users email forwarded to same destination](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Office_MailForwarding.yaml>) and [Malicious Inbox Rule](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Malicious_Inbox_Rule.yaml>)
