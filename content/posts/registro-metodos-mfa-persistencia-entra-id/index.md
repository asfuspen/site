---
title: "Registro de MFA como persistência no Entra ID: detectar, responder e proteger"
date: 2026-11-17
draft: false
description: "Como um atacante com a senha de um usuário registra o próprio método de MFA para manter o acesso, como encontrar esses registros nos logs de auditoria do Entra ID com KQL e como proteger o registro de informações de segurança com Acesso Condicional."
summary: "Como o atacante registra o próprio MFA para manter o acesso, como achar esses registros com KQL no Sentinel e como proteger o registro com Acesso Condicional."
categories: ["Identidade"]
tags: ["entra id", "mfa", "acesso condicional", "kql", "sentinel"]
series: ["Detecções com KQL"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0003", tecnica: "T1098.005", nome: "Device Registration" }
  - { tatica: "TA0004", tecnica: "T1098.005", nome: "Device Registration" }
---

Quando uma senha vaza, o MFA costuma ser a última barreira. Mas há um momento em que essa barreira ainda não existe: a conta que nunca registrou um método. O MITRE ATT&CK descreve o problema na técnica [Account Manipulation: Device Registration (T1098.005)](https://attack.mitre.org/techniques/T1098/005/): um adversário que compromete as credenciais de um usuário pode registrar um novo dispositivo para contornar a exigência inicial de MFA e ganhar acesso persistente. A mesma página lembra que o processo de autorregistro de MFA pode exigir apenas usuário e senha para cadastrar o primeiro dispositivo da conta.

O resultado é pior do que um login isolado. Depois do registro, o segundo fator está nas mãos do atacante, e trocar a senha da vítima não basta para tirá-lo da conta se o método dele continuar cadastrado.

Este artigo mostra onde esse registro aparece nos logs do Entra ID, duas consultas KQL para o Sentinel, como reagir quando o registro é suspeito e como reduzir a superfície com Acesso Condicional.

## Quem usa a técnica

A página da técnica no MITRE lista como exemplos de procedimento o APT29, que segundo o MITRE cadastrou dispositivos próprios em tenants de nuvem comprometidos, a campanha C0027, atribuída ao Scattered Spider, a campanha de comprometimento da SolarWinds e a ferramenta AADInternals. A técnica cobre duas táticas: Persistência (TA0003) e Escalação de privilégio (TA0004).

## Onde o registro aparece

A [referência de atividades do log de auditoria do Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities) tem uma seção "Authentication Methods", e a própria página diz que esses logs servem para conferir se os usuários registraram corretamente o dispositivo móvel para o MFA. As atividades listadas, todas na categoria UserManagement, incluem:

| Atividade | O que indica |
| --- | --- |
| User registered security info | O próprio usuário cadastrou um método |
| User registered all required security info | O usuário concluiu o registro exigido |
| User changed default security info | O método padrão foi trocado |
| User deleted security info | O usuário removeu um método |
| User updated security info | O usuário alterou um método existente |
| Admin registered security info | Um administrador cadastrou um método para alguém |
| Admin updated security info | Um administrador alterou um método |
| Admin deleted security info | Um administrador removeu um método |

No Sentinel, esses eventos chegam pela tabela [AuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs), que tem, entre outras, as colunas `OperationName`, `Result`, `ResultReason`, `InitiatedBy`, `TargetResources` e `CorrelationId`. `InitiatedBy` e `TargetResources` são do tipo `dynamic`, por isso as consultas abaixo extraem os campos internos com `tostring()`.

## Consulta 1: alterações de métodos nos últimos 7 dias

A primeira consulta lista quem registrou, alterou ou removeu métodos de autenticação, de qual endereço IP e para qual conta. Serve como ponto de partida para revisão manual e para entender o volume normal antes de criar qualquer alerta.

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

Vale olhar com mais atenção três situações: uma conta que troca o método padrão logo depois de registrar um método novo, um administrador registrando métodos para usuários fora de um processo conhecido e muitos registros vindos do mesmo IP para contas diferentes. Esses critérios são sugestões minhas de triagem, não regras oficiais.

<!-- Alessandro: consulta não executada em ambiente real. Confirme que OperationName traz exatamente os nomes da referência de auditoria e anote quais campos de TargetResources e ResultReason mostram o tipo de método registrado. -->

## Consulta 2: registro a partir de um IP que a conta nunca usou

A segunda consulta procura o caso típico de conta tomada: o usuário registra um método de um endereço IP que não apareceu em nenhum login com sucesso dessa mesma conta nos 30 dias anteriores. As janelas de 1 dia e 30 dias são pontos de partida meus; ajuste à retenção do seu workspace.

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

A tabela [SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) guarda os logins interativos. Um usuário novo, que ainda não tem histórico, sempre vai aparecer no resultado; por isso a consulta funciona melhor como fila de revisão do que como alerta automático. Contas criadas há poucos dias podem ser tratadas à parte.

<!-- Alessandro: consulta não executada em ambiente real. Valide o volume de resultados e se vale cruzar também com AADNonInteractiveUserSignInLogs antes de transformar em regra agendada. -->

## Como responder a um registro suspeito

A página [Manage user authentication methods for Microsoft Entra multifactor authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userdevicesettings) descreve as ações disponíveis para o administrador:

1. **Revoke sessions** invalida os refresh tokens do usuário e força uma nova autenticação nas sessões e aplicativos ativos.
2. **Require re-register MFA** desativa os tokens OATH de hardware do usuário e apaga números de telefone, apps Microsoft Authenticator e tokens OATH de software, obrigando um novo registro.
3. Os métodos também podem ser vistos e removidos um a um, inclusive pelo Microsoft Graph PowerShell, com cmdlets como `Get-MgUserAuthenticationPhoneMethod` e `Remove-MgUserAuthenticationPhoneMethod` para métodos de telefone.

A mesma página informa que a função Authentication Administrator pode exigir que outros usuários redefinam a senha, registrem o MFA de novo ou tenham as sessões revogadas.

Na prática, a ordem importa: se a senha for trocada e o método do atacante continuar cadastrado, ele pode voltar a entrar. Remova o método suspeito, revogue as sessões e só então devolva a conta ao usuário com um processo de registro controlado.

<!-- Alessandro: acrescente aqui o roteiro de resposta que você usa em incidentes de conta comprometida, se tiver um. -->

## Prevenção: proteger o próprio registro

O Entra ID permite tratar o registro de métodos como uma ação protegida. O guia [Protect security info registration with Conditional Access policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration) usa a ação de usuário **Register security information** em uma política que exige MFA de quem não está em uma rede confiável. Os passos principais:

1. Em **Users**, inclua **All users** e exclua os usuários convidados e externos, além das contas de acesso de emergência.
2. Em **Target resources**, selecione **User actions** e marque **Register security information**.
3. Em **Conditions > Locations**, inclua **Any location** e exclua **All trusted locations**.
4. Em **Grant**, use **Require authentication strength**.
5. Comece em **Report-only** e só depois ative.

O guia traz dois avisos. Primeiro, métodos de autenticação externos ainda não são compatíveis com authentication strength. Segundo, a partir de 6 de julho de 2026 as políticas que miram Register security information passam a valer também no registro de credenciais do Windows Hello for Business e do Platform SSO no macOS.

### E o usuário que ainda não tem MFA?

É aqui que entra o [Temporary Access Pass (TAP)](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass). Segundo a documentação, o TAP é uma senha temporária, de uso único ou múltiplo, e o uso mais comum é justamente o registro de métodos no primeiro acesso ou na configuração do dispositivo. O guia de Acesso Condicional confirma que o TAP satisfaz a exigência de MFA da política. Com isso, o primeiro registro deixa de depender só da senha: o TI entrega o TAP por um canal confiável, com validade curta, e o usuário cadastra o método. A documentação permite configurar a validade entre 10 minutos e 30 dias, com padrão de 1 hora. O TAP não funciona para convidados, e por isso eles ficam fora da política.

<!-- Alessandro: acrescente aqui como é ou como seria o processo de entrega de TAP para novos colaboradores nos ambientes que você administra, sem identificar as empresas. -->

## Conclusão

O registro de um método de MFA é um evento pequeno no log de auditoria, mas pode ser o momento em que um atacante transforma uma senha vazada em acesso duradouro. Três medidas cobrem a maior parte do risco: revisar os eventos de "security info" com as consultas acima, proteger a ação Register security information com Acesso Condicional e usar o TAP para que o primeiro registro não dependa só da senha. Na resposta, remova o método suspeito e revogue as sessões antes de considerar a conta limpa.

## Referências

- MITRE ATT&CK. [Account Manipulation: Device Registration (T1098.005)](https://attack.mitre.org/techniques/T1098/005/)
- Microsoft Learn. [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [Manage user authentication methods for Microsoft Entra multifactor authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userdevicesettings)
- Microsoft Learn. [Protect security info registration with Conditional Access policy](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration)
- Microsoft Learn. [Configure Temporary Access Pass to register passwordless authentication methods](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
