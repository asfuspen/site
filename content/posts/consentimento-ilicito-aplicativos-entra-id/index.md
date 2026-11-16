---
title: "Consentimento ilícito de aplicativos no Entra ID: detectar, remover e prevenir"
date: 2026-11-16
draft: false
description: "Como funciona o ataque de consentimento ilícito a aplicativos OAuth, por que trocar a senha não resolve, como encontrar as concessões no Sentinel com KQL, como removê-las e como restringir o consentimento de usuários no Entra ID."
summary: "O ataque de consentimento ilícito, por que a troca de senha não resolve, uma consulta KQL para o Sentinel, a remoção das concessões e a configuração que restringe o consentimento de usuários."
categories: ["Identidade"]
tags: ["entra id", "sentinel", "kql", "oauth", "aplicativos"]
series: ["Detecções com KQL"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0006", tecnica: "T1528", nome: "Steal Application Access Token" }
---

Nem todo phishing pede a senha. No ataque de consentimento ilícito, o atacante pede outra coisa: que a vítima autorize um aplicativo a acessar os dados dela. A [documentação do Microsoft Defender for Office 365](<https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants>) descreve o roteiro: o atacante cria um aplicativo registrado no Microsoft Entra ID e engana o usuário para que ele conceda consentimento a esse aplicativo. A partir daí, o aplicativo tem acesso aos dados no nível da conta, sem precisar de uma conta da organização.

O detalhe que muda a resposta ao incidente está na mesma página: redefinir a senha e exigir MFA não são medidas eficazes contra esse tipo de ataque. O acesso não depende da senha da vítima, e sim da concessão que ela aprovou.

O MITRE ATT&CK registra o comportamento em [Steal Application Access Token (T1528)](<https://attack.mitre.org/techniques/T1528/>), na tática Credential Access (TA0006). A técnica descreve o adversário que cria um aplicativo malicioso para obter acesso a recursos com o token OAuth do usuário e envia um link de spearphishing para que a vítima conceda esse acesso.

## Por que o usuário consegue conceder

O ponto de partida é a configuração padrão. Segundo a página [Configure how users consent to applications](<https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent>), por padrão todos os usuários podem consentir com aplicativos para permissões que não exigem consentimento de administrador. Em um locatário que nunca revisou essa configuração, qualquer usuário pode autorizar um aplicativo desconhecido a ler os dados dele.

Existem dois níveis de consentimento, e a diferença importa na triagem. A página de detecção orienta a conferir o campo `IsAdminConsent`: quando ele é `True`, quem consentiu pode ter concedido acesso amplo aos dados. Outro indicador é o `ConsentType` com valor `AllPrincipals`, que significa uma concessão válida para todos os usuários do locatário, e não só para quem clicou.

<!-- Alessandro: acrescente aqui se você já revisou a configuração de consentimento de usuários nos ambientes que administra e o que encontrou, sem dados que identifiquem o ambiente. -->

## O que procurar

A mesma página lista os sinais de uma concessão suspeita:

- **Atividade "Consent to application"** no log de auditoria do Microsoft Purview. A página avisa que a entrada pode levar de 30 minutos a 24 horas para aparecer.
- **`ConsentType` igual a `AllPrincipals`**, ou seja, consentimento para a organização inteira.
- **Permissões que contêm "Read", "Write" ou "All"**, que indicam acesso de leitura ou escrita a dados.
- **Usuários de alto valor** entre os que consentiram.
- **Nomes de aplicativo estranhos**: grafia errada, nomes genéricos demais ou com cara de ferramenta de ataque.

## A consulta no Sentinel

No Microsoft Sentinel, os eventos de auditoria do Entra ID chegam na tabela [`AuditLogs`](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs>), que tem as colunas `OperationName`, `InitiatedBy`, `TargetResources`, `Result` e `CorrelationId` usadas abaixo.

A forma de extrair o usuário, o IP, o aplicativo e o tipo de consentimento vem da regra oficial [Rare application consent](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml>), do repositório Azure-Sentinel. A consulta abaixo é uma versão simplificada para caça: lista todos os consentimentos dos últimos sete dias e marca os que valem para o locatário inteiro.

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

<!-- Alessandro: rode a consulta no seu workspace antes de aprovar. Confira se o parse de ConsentType traz o valor limpo e anote aqui em que campo de modifiedProperties aparecem as permissões concedidas, para uma próxima versão que filtre por escopo. -->

Na triagem, comece pelas linhas com `TenantWide` verdadeiro e pelos aplicativos que você não reconhece. Em seguida, abra o aplicativo em **Enterprise applications > Permissions** para ver as permissões concedidas.

Para transformar a caça em alerta, a regra Rare application consent já faz o trabalho de comparar com o histórico: ela alerta quando um usuário que nunca consentiu, ou um aplicativo que nunca recebeu consentimento, aparece no período atual. Vale ativá-la a partir do hub de conteúdo antes de escrever uma regra própria.

## Como remover a concessão

A página [Review permissions granted to enterprise applications](<https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions>) traz uma ressalva importante: no portal, em **Enterprise applications > aplicativo > Permissions**, só dá para revogar as concessões feitas por administrador. As concessões feitas por usuários precisam ser removidas pela API ou pelo PowerShell.

No Microsoft Graph PowerShell, a página usa `Get-MgOauth2PermissionGrant` para listar as permissões delegadas e `Remove-MgOauth2PermissionGrant` para removê-las:

```powershell
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<id-da-concessao>"
```

Para permissões de aplicativo, os cmdlets são `Get-MgServicePrincipalAppRoleAssignment` e `Remove-MgServicePrincipalAppRoleAssignedTo`. Siga a página para os parâmetros de cada caso.

A página de detecção acrescenta uma medida de curto prazo: bloquear a entrada na conta afetada enquanto a investigação acontece.

Remover a concessão não basta sozinho. A mesma página do Entra avisa que revogar a permissão atual não impede o usuário de consentir de novo. Para isso, é preciso mudar a configuração de consentimento.

<!-- Alessandro: acrescente aqui seu roteiro de resposta, por exemplo quem você avisa e como confirma que o aplicativo não acessou dados depois da remoção. -->

## Prevenção

A página de configuração de consentimento oferece duas políticas prontas da Microsoft:

| ID da política | O que permite |
|---|---|
| `microsoft-user-default-low` | Consentimento de usuários para aplicativos de editores verificados, para permissões selecionadas |
| `microsoft-user-default-legacy` | Consentimento de usuários para aplicativos |

Também é possível não permitir consentimento de usuários. Pelo PowerShell, a configuração é feita com `Update-MgPolicyAuthorizationPolicy`, depois de conectar com `Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"`. Um cuidado: o exemplo de PowerShell da página repete o prefixo `managePermissionGrantsForSelf` no ID da política, enquanto o exemplo do Graph usa `managePermissionGrantsForSelf.microsoft-user-default-low`. Confira o valor antes de aplicar.

A mudança só vale para consentimentos futuros. As concessões que já existem continuam ativas, por isso a revisão com a consulta acima deve vir junto.

Com o consentimento restrito, entra o [fluxo de consentimento de administrador](<https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow>): quando o usuário tenta acessar um aplicativo e não pode consentir, ele envia uma solicitação de aprovação, que chega por e-mail aos revisores designados. Isso evita que a restrição vire um bloqueio sem saída para quem precisa de um aplicativo legítimo.

Por fim, a página de detecção recomenda revisar as concessões de consentimento toda semana e usar as políticas de aplicativos OAuth do Microsoft Defender for Cloud Apps.

## Conclusão

O consentimento ilícito explora um recurso legítimo e não depende da senha, então a resposta clássica de redefinir credenciais não remove o acesso. A defesa tem três partes: restringir o consentimento de usuários a editores verificados e a permissões selecionadas, com o fluxo de aprovação para os pedidos legítimos; acompanhar a atividade "Consent to application" no Sentinel; e, no incidente, remover a concessão pelo PowerShell, porque o portal não revoga o que o usuário concedeu.

## Referências

- Microsoft Learn. [Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
- Microsoft Learn. [Configure how users consent to applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- Microsoft Learn. [Configure the admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow)
- Microsoft Learn. [Review permissions granted to enterprise applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- Azure-Sentinel (GitHub). [Rare application consent](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml)
- MITRE ATT&CK. [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/)
