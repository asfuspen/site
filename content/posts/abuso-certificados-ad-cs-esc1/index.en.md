---
title: "AD CS and the misconfigured certificate template (ESC1): posture, detection and remediation"
date: 2026-11-14
draft: false
description: "How an AD CS certificate template that accepts a requester-supplied name lets anyone impersonate any domain user, and how to find, detect and fix it with Defender for Identity, Defender XDR and Sentinel."
summary: "How a misconfigured AD CS certificate template lets anyone impersonate any user, and how to find, detect and fix it."
categories: ["Detection"]
tags: ["kql", "sentinel", "defender xdr", "defender for identity", "active directory", "ad cs"]
series: ["KQL detections"]
nivel: "avancado"
mitre:
  - { tatica: "TA0006", tecnica: "T1649", nome: "Steal or Forge Authentication Certificates" }
---

In Active Directory, a certificate can be worth as much as a password. The MITRE ATT&CK page for [Steal or Forge Authentication Certificates (T1649)](<https://attack.mitre.org/techniques/T1649/>) states that Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts. The same page explains that the subject alternative name (SAN) values define the certificate owner's alternate names, and that misconfigurations can allow privilege escalation through the identities associated with a certificate.

The most direct case of this problem has a name: ESC1. It was described by Will Schroeder and Lee Christensen, of SpecterOps, in [Certified Pre-Owned](<https://specterops.io/blog/2021/06/17/certified-pre-owned/>), published on June 17, 2021. Microsoft sums up the risk in the Defender for Identity [certificates posture assessment](<https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>): a template in this condition allows any unprivileged user to take over an arbitrary user, including a domain admin.

This article covers the full cycle: the conditions that make a template vulnerable, how to find those templates, which alerts Defender for Identity raises, where the events show up in Defender XDR and Sentinel, the remediation, and the limits of what is written here.

## What makes a template vulnerable

The SpecterOps text lists the ESC1 conditions. All of them must be present at the same time:

| Condition | What it means |
|---|---|
| The Enterprise CA grants low-privileged users enrollment rights | Any regular user can request certificates from that CA |
| Manager approval is disabled | The request is served with no human review |
| No authorized signatures are required | The request does not need to be signed by another certificate |
| The template security descriptor is overly permissive | The template grants enrollment to low-privileged users |
| The template defines EKUs that enable authentication | The issued certificate can be used to sign in to the domain |
| The template allows requesters to specify a SAN in the request | The requester chooses whose name the certificate carries |

The last condition is the one that defines the problem. According to the text, when the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag is present in the template's `mspki-certificate-name-flag` property, a requester can specify the SAN. In the certificate templates console (`certtmpl.msc`), this option is shown as "Supply in request".

The EKUs the authors identify as enough for domain authentication are:

- Client Authentication (`1.3.6.1.5.5.7.3.2`)
- PKINIT Client Authentication (`1.3.6.1.5.2.3.4`)
- Smart Card Logon (`1.3.6.1.4.1.311.20.2.2`)
- Any Purpose (`2.5.29.37.0`)
- No EKU (SubCA)

About the PKINIT EKU, the text notes that it is not present in AD CS deployments by default and needs to be added manually.

The practical outcome: a regular user requests a certificate with that template, writes an administrator's name in the SAN and receives a certificate that is valid to authenticate as that administrator. No password was stolen and no software vulnerability was exploited. ATT&CK records that the APT29 group abused misconfigured AD CS certificate templates.

<!-- Alessandro: if you have found a template like this in an audit or in a lab, describe here how it was configured, without data that identifies the environment. -->

## How to find vulnerable templates

### Defender for Identity posture assessment

The [certificates assessments page](<https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>) lists ten assessments. The one this article is about is called "Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)" and is marked as Preview. The others cover further variations described in the same SpecterOps work and in later research:

| Assessment | Code |
|---|---|
| Prevent users to request a certificate valid for arbitrary users based on the certificate template | ESC1 |
| Edit overly permissive certificate template with privileged EKU (Any purpose EKU or No EKU) | ESC2 |
| Edit misconfigured enrollment agent certificate template | ESC3 |
| Edit misconfigured certificate templates owner | ESC4 |
| Edit misconfigured certificate templates ACL | ESC4 |
| Edit vulnerable Certificate Authority setting | ESC6 |
| Edit misconfigured Certificate Authority ACL | ESC7 |
| Edit insecure ADCS certificate enrollment IIS endpoints | ESC8 |
| Enforce encryption for RPC certificate enrollment interface | ESC11 |
| Prevent Certificate Enrollment with arbitrary Application Policies | ESC15 |

Some of these assessments are only available to customers who installed a sensor on an AD CS server. The page carries that note on the ESC6, ESC8 and ESC15 assessments. The ESC1 section does not show it.

### Manual review

Without Defender for Identity, ATT&CK mitigation M1047 (Audit) points the way: check certificate enrollment permissions and overly permissive published templates, using the certification authority console (`certsrv.msc`) or `certutil.exe`. What to look for in each published template are the six conditions in the table above.

<!-- Alessandro: add here the command or procedure you use to list published templates and their permissions, after validating it in your lab. I did not include the syntax because I did not find it on an official page I was able to open. -->

## What Defender for Identity alerts on

The [Defender for Identity XDR alerts list](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr>) has one alert specific to this scenario and others covering the steps around it:

| Alert | Severity | Technique | What it indicates |
|---|---|---|---|
| Possible Active Directory Certificate Services enumeration | Medium | T1649, T1087 | AD CS enumeration activity originating from an IP address |
| Suspicious Active Directory Certificate Services (AD CS) misconfigured certificate template abuse (ESC1) | High | T1649 | A certificate request using a template that allows the requester to supply arbitrary SAN values |
| Suspicious Active Directory Certificate Services (AD CS) certificate request | High | T1649 | A certificate request to AD CS with anomalous characteristics |
| Suspicious Kerberos PKINIT authentication (AS-REQ) | Medium | T1649, T1558 | Possible use of an unauthorized certificate to authenticate as the affected account |
| Kerberos authentication following AD CS compromise | High | T1078.002, T1649 | An account signed in using Kerberos with a malicious certificate |

The table follows the likely order of an attack: enumerate the templates, request the certificate and use it to authenticate. Reading the alerts as a sequence is my interpretation, not a statement from the documentation.

The [classic alerts list](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic>) includes "Suspicious certificate usage over Kerberos protocol (PKINIT)", external ID 2425, high severity, with the note that it is only supported by Defender for Identity sensors on AD CS.

### The sensor on the AD CS server

The page [Configure sensors for AD FS, AD CS, and Microsoft Entra Connect](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services>) has three points that prevent surprises:

- You don't need to install sensors on AD CS servers that are offline.
- With the v2.x sensor, support covers only AD CS servers with the Certification Authority role service.
- The v2.x sensor on AD CS can't use the local service account to connect to the domain. A Directory Service Account must be configured.

## Enable auditing on the CA

Without auditing there is no event for the sensor or for Sentinel. The page [Configure Windows event auditing](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection>) asks for two settings.

The first is the advanced audit policy, under `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Certification Services`, with success and failure events enabled.

The second is the CA's own audit filter. The page gives both commands:

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
```

The service must be restarted for the change to take effect. In the console, the equivalent path is to open Certification Authority, right-click the CA name, select Properties and tick the events on the Auditing tab.

The page warns about one event type: auditing the start and stop of the service might cause restart delays when the AD CS database is large. The guidance is to remove irrelevant entries from the database or not enable that specific type.

The AD CS events Defender for Identity requires are these:

| Event | Description |
|---|---|
| 4870 | Certificate Services revoked a certificate |
| 4882 | The security permissions for Certificate Services changed |
| 4885 | The audit filter for Certificate Services changed |
| 4887 | Certificate Services approved a certificate request and issued a certificate |
| 4888 | Certificate Services denied a certificate request |
| 4890 | The certificate manager settings for Certificate Services changed |
| 4896 | One or more rows have been deleted from the certificate database |

Event 4886 (Certificate Services received a certificate request) is not on that list, but it is on the [Audit Certification Services](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services>) page and is useful in Sentinel. That page estimates the subcategory's volume as low to medium on servers that provide AD CS role services.

## Hunting in Defender XDR

With the sensor installed, Microsoft itself gives the validation query on the sensor configuration page:

```kql
IdentityDirectoryEvents
| where Protocol == "Adcs"
```

According to the page, the results show failed and successful certificate issuance. From there, a view by event type and account helps you learn the normal volume before looking for exceptions. The columns used are in the [table reference](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table>):

```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where Protocol == "Adcs"
| summarize Events = count(), LastSeen = max(Timestamp) by ActionType, AccountUpn, DeviceName
| order by Events desc
```

To look at events one by one, with the details the sensor records:

```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where Protocol == "Adcs"
| project Timestamp, ActionType, AccountUpn, TargetAccountUpn, DeviceName, IPAddress, AdditionalFields
| order by Timestamp desc
```

An important limit: the table reference does not list the `ActionType` values or the contents of `AdditionalFields` for AD CS events. It points to the built-in schema reference in the Defender portal. That is why the queries above do not filter by template name or compare the requester with the certificate subject. That refinement depends on seeing real data.

<!-- Alessandro: run both queries in your environment and note here which ActionType values appear and which AdditionalFields entries carry the template and the subject. With that, the filter comparing requester and subject can be written. -->

## Hunting in Microsoft Sentinel

In Sentinel, CA events land in the [`SecurityEvent`](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent>) table. Before writing the query, check which event set is collected. The [Windows security event sets](<https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference>) page shows that events 4886, 4887 and 4888 are part of the Common set and are not part of the Minimal set. A workspace that collects only the Minimal set sees no certificate requests.

The first query gives the daily volume per server:

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4886, 4887, 4888)
| summarize Requests = countif(EventID == 4886),
            Issued = countif(EventID == 4887),
            Denied = countif(EventID == 4888)
    by Computer, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

The second returns issued certificates with the raw event content:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4887
| project TimeGenerated, Computer, Account, Activity, EventData
| order by TimeGenerated desc
```

The `EventID`, `Computer`, `Account`, `Activity` and `EventData` columns are in the table reference. The contents of `EventData` for event 4887 were not confirmed: the documentation page for that event did not open during research. The table has columns whose names start with `Template`, but their descriptions refer to event messages and GPO templates, not certificate templates. Do not use those columns to filter by template before looking at the data.

<!-- Alessandro: validate both queries in your workspace and record here the fields that appear in EventData for event 4887. The detection that matters is a certificate issued to a subject different from the requester. -->

## Remediation

The Defender for Identity ESC1 assessment lists five actions for a vulnerable template:

1. Turn off the "Supply in the request" configuration.
2. Remove any EKUs that enable user authentication, such as Client Authentication, Smartcard logon, PKINIT client authentication or Any purpose.
3. Remove overly permissive enrollment permissions, which allow any user to enroll a certificate based on that template.
4. Turn on the CA certificate manager approval requirement.
5. Remove the certificate template from being published by any CA.

Each action breaks one of the conditions in the first table, and breaking one is enough for ESC1 to stop existing. The choice depends on who uses the template today. A caution of my own, not from the documentation: before changing it, find out which systems request certificates with it, because turning off "Supply in the request" on a template used by web servers, for example, interrupts the renewal of those certificates.

The ATT&CK mitigations for T1649 point in the same direction and add context:

- **M1015, Active Directory Configuration:** treat CA servers as tier 0 assets, consider disabling the use of SAN in authentication protocol settings, and consider requiring CA certificate manager approval for templates with SAN.
- **M1047, Audit:** review enrollment permissions and published templates.
- **M1042, Disable or Remove Feature or Program:** disable old protocols such as NTLM and AD CS web enrollment roles that are not needed.
- **M1041, Encrypt Sensitive Information:** protect certificates and private keys, for example with TPM or HSM.

### Strong certificate mapping

A complementary protection came through the operating system. [KB5014754](<https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16>) describes changes to certificate-based authentication on domain controllers, tied to CVE-2022-34691, CVE-2022-26931 and CVE-2022-26923. The idea is to require a strong mapping between the certificate and the account. The article considers mappings strong when they are based on identifiers that cannot be reused.

According to the article, domain controllers move to Full Enforcement mode with the February 2025 security update, and authentication is denied if a certificate cannot be strongly mapped. Compatibility mode could be restored until the September 9, 2025 update. After that, the `StrongCertificateBindingEnforcement` registry key is no longer supported.

The article also documents KDC events that help an investigation, among them the one for a certificate with no strong mapping and the one for a user SID that does not match the certificate SID. The numbering of these events varies by Windows Server version. Check the table in the article for your version.

This protection does not replace fixing the template. It deals with how the domain controller associates the certificate with the account. The vulnerable template remains a configuration error that must be fixed at the source.

## Responding to an incident

When an ESC1 alert is confirmed, there is a difference from a password incident: the authentication described in this article uses the certificate, not the password. So the investigation needs to list the certificates issued during the period, in addition to handling the account's credentials. This recommendation is my interpretation based on how the technique works. I did not find an official response procedure on the pages consulted.

<!-- Alessandro: add your response procedure here, including how you locate and revoke certificates issued during the incident window. -->

## What this article does not cover

- **The other variations.** ESC2 to ESC15 have their own conditions and fixes. The Defender for Identity assessments page is the best starting point for each.
- **Filtering by template and subject.** The queries show AD CS events but do not isolate a request made in another account's name, because the required fields are not documented on the pages consulted.
- **Scheduled analytics rule.** Turning the query into a rule only makes sense after learning the fields and the volume in a real environment.
- **Validation in a real environment.** None of the queries was run in a tenant or workspace.
- **The full list of SpecterOps recommendations.** The prevention and detection items are in the authors' full whitepaper, which was not read for this article.

## Conclusion

ESC1 does not depend on a software flaw. It comes from a certificate template that combines three permissions which, together, become a shortcut to any identity in the domain: open enrollment, an authentication EKU and a name chosen by the requester. Defense starts with posture, by reviewing published templates. It continues with CA auditing, without which there is no event to analyze. And it ends with fixing the template, keeping in mind that certificate authentication does not depend on the account's password.

The previous article in the series covers [email forwarding rules]({{< relref "/posts/regras-encaminhamento-email-exchange-online" >}}), a case where resetting the password does not end the attacker's access.

## References

- MITRE ATT&CK. [Steal or Forge Authentication Certificates (T1649)](<https://attack.mitre.org/techniques/T1649/>)
- SpecterOps. Will Schroeder and Lee Christensen. [Certified Pre-Owned](<https://specterops.io/blog/2021/06/17/certified-pre-owned/>), June 17, 2021
- Microsoft Learn. [Security assessment: Certificates](<https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>)
- Microsoft Learn. [Microsoft Defender for Identity XDR security alerts](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr>)
- Microsoft Learn. [Microsoft Defender for Identity classic security alerts](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic>)
- Microsoft Learn. [Configure sensors for AD FS, AD CS, and Microsoft Entra Connect](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services>)
- Microsoft Learn. [Configure Windows event auditing](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection>)
- Microsoft Learn. [Audit Certification Services](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services>)
- Microsoft Learn. [IdentityDirectoryEvents table](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table>)
- Microsoft Learn. [SecurityEvent table reference](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent>)
- Microsoft Learn. [Windows security event sets that can be sent to Microsoft Sentinel](<https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference>)
- Microsoft Support. [KB5014754: Certificate-based authentication changes on Windows domain controllers](<https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16>)
