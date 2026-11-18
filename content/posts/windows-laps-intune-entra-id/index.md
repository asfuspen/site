---
title: "Windows LAPS com Intune e Entra ID: senha única de administrador local em cada máquina"
date: 2026-11-18
draft: false
description: "Como habilitar o Windows LAPS no Microsoft Entra ID, configurar a política no Intune, controlar quem pode ler a senha do administrador local e monitorar as recuperações de senha com KQL no Microsoft Sentinel."
summary: "Passo a passo para habilitar o Windows LAPS com Intune e Entra ID, controlar quem lê a senha do administrador local e monitorar as recuperações com KQL."
categories: ["Endpoint"]
tags: ["intune", "entra id", "windows laps", "kql", "sentinel", "contas privilegiadas"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0004", tecnica: "T1078.003", nome: "Local Accounts" }
  - { tatica: "TA0008", tecnica: "T1550.002", nome: "Pass the Hash" }
---

Em muitos ambientes, a conta de administrador local de todas as estações tem a mesma senha, definida na imagem do sistema anos atrás. Basta comprometer uma máquina para ter acesso administrativo às outras. O MITRE ATT&CK descreve esse abuso em [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/): a reutilização de senha pode permitir o abuso de contas locais em um conjunto de máquinas para escalação de privilégio e movimento lateral.

A mesma página traz duas mitigações diretas. A M1027 pede senhas complexas e únicas para as contas de administrador local em todos os sistemas da rede, e a M1026 afirma que implementar o LAPS ajuda a evitar a reutilização dessas credenciais. Em [Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/), a orientação é limitar a sobreposição de credenciais entre sistemas para reduzir o movimento lateral.

Este artigo mostra como fazer isso com o Windows LAPS, o Microsoft Intune e o Microsoft Entra ID, e como acompanhar quem consulta as senhas.

## O que é o Windows LAPS

O Windows LAPS gira e guarda a senha de uma conta de administrador local em cada dispositivo. Segundo a [visão geral da Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview), é uma implementação nativa do Windows, separada do produto antigo, e não exige instalar o Microsoft LAPS legado. O LAPS legado está obsoleto a partir do Windows 11 23H2, e as versões mais novas bloqueiam a instalação do pacote MSI antigo. O suporte ao Entra ID e ao Intune está disponível de forma geral desde 23 de outubro de 2023.

Pontos de compatibilidade que valem conferir antes de começar:

- **Sistemas:** Windows 11 23H2 e posteriores, e versões anteriores do Windows 11, Windows 10, Windows Server 2022 e 2019 com a atualização de 11 de abril de 2023 ou posterior. A página lembra que o Windows 10 saiu de suporte em 14 de outubro de 2025.
- **Tipo de ingresso:** a [documentação do Entra](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords) informa que o LAPS com backup no Entra funciona só em dispositivos Microsoft Entra joined ou Microsoft Entra hybrid joined. Dispositivos apenas registrados não são suportados.

## Passo 1: habilitar o LAPS no Entra ID

Com pelo menos a função Cloud Device Administrator, acesse **Entra ID > Devices > Overview > Device settings**, marque **Yes** em **Enable Local Administrator Password Solution (LAPS)** e salve. A [política do Intune](https://learn.microsoft.com/en-us/intune/device-security/laps/deploy-policy) depende dessa configuração, e a documentação pede para confirmar que o LAPS está habilitado no Entra antes de distribuí-la.

## Passo 2: criar a política no Intune

No centro de administração do Intune, vá em **Endpoint security > Account protection > Create Policy**, escolha a plataforma **Windows** e o perfil **Local admin password solution (Windows LAPS)**. A Microsoft recomenda atribuir a política a grupos de dispositivos e evitar políticas em conflito, que podem impedir o processamento. As configurações do provedor CSP do LAPS têm precedência sobre GPOs e sobre o LAPS legado.

As configurações principais, com os valores da [referência de políticas](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings):

| Configuração | O que faz | Padrão |
|---|---|---|
| BackupDirectory | Destino do backup: 0 desativado, 1 Entra ID, 2 Active Directory | 0 (desativado) |
| AdministratorAccountName | Conta gerenciada; vazio gerencia o administrador interno. O LAPS não cria a conta | Administrador interno |
| PasswordAgeDays | Idade máxima da senha; com backup no Entra o mínimo é 7 dias | 30 |
| PasswordComplexity | Composição da senha (4 = maiúsculas, minúsculas, números e especiais) | 4 |
| PasswordLength | Tamanho, de 8 a 64 | 14 |
| PostAuthenticationActions | Ação depois que a conta é usada (1 redefine; 3 redefine e encerra a sessão; 5 redefine e reinicia) | 3 |
| PostAuthenticationResetDelay | Horas até executar essa ação, de 0 a 24 | 24 |

O ponto mais esquecido é o `BackupDirectory`: o padrão é desativado, então a política só faz efeito quando você escolhe o Entra ID. Se escolher Active Directory em um dispositivo que não está no domínio, o Intune aplica a política sem erro, mas o LAPS não consegue fazer o backup.

As ações pós-autenticação limitam o tempo de vida de uma senha que foi vista: depois que alguém usa a conta, o LAPS troca a senha ao fim do intervalo. Reduzir o `PostAuthenticationResetDelay` para poucas horas é uma escolha minha para quem usa a conta em atendimentos curtos, não um valor oficial.

No Windows 11 24H2 e no Windows Server 2025, o LAPS também pode gerenciar a conta automaticamente, criando uma conta própria (prefixo padrão `WLapsAdmin`) e, se configurado, acrescentando um sufixo aleatório de seis dígitos ao nome a cada rotação.

<!-- Alessandro: acrescente aqui sua experiência com a configuração usada nos ambientes que você administra, sem citar nomes de empresas. -->

## Passo 3: decidir quem pode ler a senha

Ler a senha exige a permissão `microsoft.directory/deviceLocalCredentials/password/read`. Entre as funções internas, a documentação do Entra lista Cloud Device Administrator e Intune Administrator. Helpdesk Administrator, Security Administrator e Security Reader veem só os metadados, sem a senha.

Para reduzir o alcance:

- **Função personalizada:** com Entra ID P1 ou P2, é possível criar uma função só com a permissão de leitura da senha.
- **Unidades administrativas:** a função Cloud Device Administrator pode ser atribuída com escopo em uma unidade administrativa que contenha só os dispositivos de uma equipe.
- **Acesso Condicional:** políticas direcionadas às funções internas, como exigir MFA para administradores, protegem a recuperação das senhas. A mesma página diz que funções personalizadas e com escopo de unidade administrativa não são suportadas nesse direcionamento.

Um detalhe para o plano de resposta: não há como recuperar no Entra ID a senha de um dispositivo excluído.

## Passo 4: consultar e girar a senha

No Intune, a senha aparece em **Devices > All devices >** dispositivo **> Monitor > Local admin password**, com a data da última e da próxima rotação. Visualizar a senha gera um evento de auditoria. A ação **Rotate Local admin password** força a troca, mas tem limites documentados: o dispositivo precisa ter feito pelo menos um backup, um dispositivo Entra joined precisa estar online e a ação não funciona em massa. No Entra, cada recuperação e cada atualização aparecem no log de auditoria com as atividades `Recover device local administrator password` e `Update device local administrator password`.

## Monitorar as recuperações com KQL

Quem lê várias senhas em pouco tempo pode estar preparando movimento lateral, seja um operador apressado ou uma conta privilegiada comprometida. Com os logs de auditoria do Entra enviados ao Microsoft Sentinel, a consulta abaixo resume as recuperações por quem as executou:

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

As colunas `OperationName`, `InitiatedBy`, `TargetResources` e `Result` estão na [referência da tabela AuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs). Os campos internos de `InitiatedBy` e `TargetResources` precisam ser conferidos nos seus logs. Para virar regra agendada, um ponto de partida meu é alertar quando a mesma pessoa recupera senhas de mais de cinco dispositivos em uma hora; ajuste ao volume do seu suporte.

<!-- Alessandro: consulta não executada em ambiente real. Valide o nome da atividade, os campos de TargetResources e InitiatedBy e o limite de alerta antes de publicar como regra. -->

## Conclusão

O Windows LAPS resolve um problema antigo com pouco esforço: habilitar no Entra, uma política no Intune com backup no Entra ID e uma decisão clara sobre quem pode ler as senhas. A auditoria que vem junto transforma cada leitura de senha em um evento que pode ser revisado e, com KQL, em alerta.

## Referências

- Microsoft Learn. [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- Microsoft Learn. [Windows Local Administrator Password Solution in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords)
- Microsoft Learn. [Manage Windows LAPS policy with Microsoft Intune](https://learn.microsoft.com/en-us/intune/device-security/laps/deploy-policy)
- Microsoft Learn. [Monitoramento do Windows LAPS no Intune](https://learn.microsoft.com/en-us/intune/device-security/laps/monitor)
- Microsoft Learn. [Configure policy settings for Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- MITRE ATT&CK. [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/)
- MITRE ATT&CK. [Use Alternate Authentication Material: Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)
