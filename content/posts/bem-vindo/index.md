---
title: "Bem-vindo ao blog"
date: 2026-11-12
draft: false
description: "Por que este blog existe e o que você vai encontrar por aqui."
summary: "Por que este blog existe e o que você vai encontrar por aqui."
categories: ["Geral"]
tags: ["comunidade", "microsoft-security"]
nivel: "iniciante"
---

Este é o primeiro post do blog. Ele serve de exemplo do formato dos artigos e pode ser editado ou apagado à vontade.

## O que você vai encontrar aqui

- **Tutoriais práticos** de configuração e operação de ferramentas de segurança.
- **Detecção e resposta**, com consultas KQL comentadas para Microsoft Sentinel e Defender XDR.
- **Identidade e acesso**, com boas práticas de Entra ID, acesso condicional e Zero Trust.

## Exemplo de bloco de código

A consulta abaixo lista as contas com mais falhas de login nas últimas 24 horas no Microsoft Sentinel:

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize Falhas = count() by UserPrincipalName, IPAddress
| top 10 by Falhas desc
```

## Próximos passos

Os próximos artigos entram em temas específicos. Se tiver uma sugestão de assunto, entre em contato pelos links da página [Sobre]({{< relref "/sobre" >}}).
