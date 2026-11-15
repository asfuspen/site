---
title: "Phishing de código de dispositivo: como bloquear e detectar no Entra ID"
date: 2026-11-13
draft: false
description: "Como o phishing de código de dispositivo rouba tokens sem pedir senha, como bloquear o fluxo com Acesso Condicional no Microsoft Entra ID e como medir o uso e detectar abusos com KQL no Sentinel."
summary: "Como o phishing de código de dispositivo rouba tokens sem pedir senha, como bloquear o fluxo com Acesso Condicional e como detectar abusos com KQL."
categories: ["Identidade"]
tags: ["entra id", "acesso condicional", "kql", "sentinel", "phishing"]
series: ["Detecções com KQL"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0001", tecnica: "T1566.002", nome: "Spearphishing Link" }
  - { tatica: "TA0006", tecnica: "T1528", nome: "Steal Application Access Token" }
---

O fluxo de código de dispositivo existe para um problema legítimo: entrar em um equipamento que não tem teclado ou navegador. A [documentação da plataforma de identidade da Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code) cita TVs, dispositivos IoT e impressoras. O aparelho mostra um código, a pessoa abre uma página de login em outro dispositivo, digita o código e se autentica ali. Enquanto isso, o aparelho consulta o endpoint de token até receber o acesso.

O problema é que nada nesse fluxo garante que quem gerou o código é quem vai usá-lo. Se o atacante gera o código e convence a vítima a digitá-lo, a vítima faz o login completo, com MFA, na página verdadeira da Microsoft, e quem recebe os tokens é o atacante. O MITRE ATT&CK cita essa variante na técnica [Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/), com o nome "device code phishing".

## O caso Storm-2372

Em fevereiro de 2025, a Microsoft Threat Intelligence [publicou a análise de uma campanha](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) atribuída ao Storm-2372, ativa desde agosto de 2024. Uma atualização de julho de 2026 no mesmo texto passou a avaliar o grupo como um subconjunto de acesso inicial do Midnight Blizzard. Segundo o relato:

1. O atacante criava afinidade com a vítima se passando por uma pessoa relevante para ela, em mensageiros como WhatsApp, Signal e Microsoft Teams.
2. Em seguida, mandava um convite falso para reunião ou evento online. O "código da reunião" era, na verdade, um código de dispositivo gerado pelo atacante.
3. Quando a vítima digitava o código na página legítima, o atacante recebia os tokens de acesso e de atualização e passava a ler e-mail e armazenamento em nuvem sem precisar da senha.
4. Com a conta tomada, o grupo enviava novos phishings internos e usava o Microsoft Graph para buscar mensagens com termos como "password", "admin", "credentials" e "secret", exfiltrando o que encontrava.

O relatório também conta que o grupo passou a usar o ID de cliente do Microsoft Authentication Broker, o que permitia registrar um dispositivo controlado pelo atacante no Entra ID e obter um Primary Refresh Token. Os alvos incluíam governo, ONGs, tecnologia, defesa, telecomunicações, saúde, ensino superior e energia.

O código tem prazo curto: a documentação do fluxo informa que o usuário tem 15 minutos para entrar a partir do momento em que a solicitação é feita. Por isso o atacante precisa da conversa em tempo real ou de um convite com hora marcada.

## Primeiro passo: medir o uso legítimo

Antes de bloquear, descubra quem usa o fluxo hoje. A página sobre [fluxos de autenticação no Acesso Condicional](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows) sugere criar a política em modo somente relatório ou filtrar os logs de login pelo protocolo de autenticação. No Sentinel, a coluna `AuthenticationProtocol` existe nas tabelas [SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) e [AADNonInteractiveUserSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs), e `deviceCode` é um dos valores documentados.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol == "deviceCode"
| summarize SignIns = count(), Successes = countif(ResultType == "0"),
    Users = dcount(UserPrincipalName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by AppDisplayName
| order by SignIns desc
```

O resultado mostra quais aplicativos dependem do fluxo e quantas pessoas os usam. A janela de 30 dias é um ponto de partida meu, não um valor oficial; ajuste à retenção do seu workspace.

<!-- Alessandro: valide a consulta em ambiente real e acrescente aqui quais aplicativos costumam aparecer (salas de reunião, ferramentas de linha de comando, scripts de administração). -->

## Bloqueio com Acesso Condicional

A recomendação da Microsoft é direta: permitir o fluxo de código de dispositivo só onde for necessário e bloqueá-lo sempre que possível. O guia [Block authentication flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows) descreve a política:

1. Entre no centro de administração do Microsoft Entra com, no mínimo, a função Conditional Access Administrator.
2. Vá em **Entra ID > Conditional Access > Policies** e selecione **New policy**.
3. Em **Users or workload identities**, inclua todos os usuários e exclua as contas de acesso de emergência (break-glass) e outras contas necessárias. O guia pede para auditar essa lista de exclusão com frequência.
4. Em **Target resources**, inclua **All resources**.
5. Em **Conditions > Authentication Flows**, marque **Configure = Yes** e selecione **Device code flow**.
6. Em **Grant**, selecione **Block access**.
7. Crie a política em **Report-only**, confira o impacto e depois mude para **On**.

Quando houver um uso legítimo que não pode ser substituído, a página de conceito dá um exemplo de exceção: se salas de reunião com dispositivos Android dependem do fluxo, bloqueie em todo lugar, menos para dispositivos Android em um local de rede específico.

Dois pontos da documentação evitam surpresas depois da ativação:

- **Rastreamento de protocolo.** Uma sessão iniciada por código de dispositivo fica marcada, e a marca continua nas renovações de token. Uma requisição posterior que não usa o fluxo pode ser bloqueada pela política. Nesse caso o usuário recebe o erro `AADSTS530036`, e a documentação diz que o bloqueio é esperado. No log, a propriedade "original transfer method" mostra "Device code flow"; nas tabelas do Sentinel a coluna equivalente é `OriginalTransferMethod`.
- **Registro de dispositivos.** Desde setembro de 2024, políticas de fluxo de autenticação que miram todos os recursos também valem para o Device Registration Service. Se a organização registra dispositivos usando código de dispositivo, exclua esse recurso da política.

<!-- Alessandro: acrescente aqui sua experiência ao implantar essa política e as exceções que precisou manter. -->

## Detecção: primeiro uso por usuário

Enquanto a política está em modo somente relatório, ou para as contas que ficaram de fora, vale alertar quando um usuário conclui um login por código de dispositivo pela primeira vez em 30 dias:

```kql
let Lookback = 30d;
let KnownUsers = SigninLogs
    | where TimeGenerated between (ago(Lookback) .. ago(1d))
    | where AuthenticationProtocol == "deviceCode"
    | where ResultType == "0"
    | distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == "0"
| where UserPrincipalName !in (KnownUsers)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
    RiskLevelDuringSignIn, ConditionalAccessStatus
| order by TimeGenerated desc
```

Na triagem, compare o IP e o aplicativo com o que o usuário costuma usar e pergunte a ele se digitou um código recentemente. O blog do Storm-2372 traz também consultas de caça para o Defender XDR que cruzam cliques em URLs de login por dispositivo com logins arriscados e procuram dispositivos registrados pelo Device Registration Service.

<!-- Alessandro: consulta não executada em ambiente real. Valide os nomes de colunas e o volume de alertas antes de transformar em regra agendada. -->

## Se uma conta foi comprometida

Trocar a senha não basta, porque o atacante tem tokens. Entre as mitigações do relatório da Microsoft estão revogar os tokens de atualização do usuário com `revokeSignInSessions`, exigir MFA com métodos resistentes a phishing, aplicar políticas de risco de login, bloquear a autenticação legada e restringir quem pode registrar dispositivos. Revise também os dispositivos registrados na conta, por causa da técnica de registro descrita no relatório.

## Conclusão

O phishing de código de dispositivo passa pelo MFA porque a vítima faz o login de verdade. A defesa mais efetiva é tirar o fluxo de quem não precisa dele: medir o uso, criar a política em modo somente relatório, manter exceções documentadas e ativar o bloqueio. As duas consultas deste artigo estão na [biblioteca KQL]({{< relref "/kql" >}}) do site.

## Referências

- Microsoft Learn. [Microsoft identity platform and the OAuth 2.0 device authorization grant flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- Microsoft Learn. [Conditional Access: Authentication flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)
- Microsoft Learn. [Block authentication flows with Conditional Access policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)
- Microsoft Security Blog. [Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- MITRE ATT&CK. [Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/)
- MITRE ATT&CK. [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [AADNonInteractiveUserSignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
