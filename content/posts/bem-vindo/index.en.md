---
title: "Welcome to the blog"
date: 2026-11-12
draft: false
description: "Why this blog exists and what you will find here."
summary: "Why this blog exists and what you will find here."
categories: ["General"]
tags: ["community", "microsoft-security"]
nivel: "iniciante"
featured: true
---

This is the first post on the blog. It works as a sample of the post format and can be edited or removed at any time.

## What you will find here

- **Hands-on tutorials** on configuring and operating security tools.
- **Detection and response**, with commented KQL queries for Microsoft Sentinel and Defender XDR.
- **Identity and access**, with good practices for Entra ID, Conditional Access and Zero Trust.
- **Lab notes**, with tests, mistakes and lessons learned.

## Code block example

The query below lists the accounts with the most failed sign-ins in the last 24 hours in Microsoft Sentinel:

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize Failures = count() by UserPrincipalName, IPAddress
| top 10 by Failures desc
```

## Next steps

The next posts go deeper into specific topics. If you have a subject to suggest, reach out through the links on the [About]({{< relref "/sobre" >}}) page.
