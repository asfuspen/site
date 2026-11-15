---
title: "Contas de acesso de emergência no Entra ID: configuração, monitoramento e testes"
date: 2026-11-15
draft: false
description: "Boas práticas da Microsoft para contas de acesso de emergência (break-glass) no Microsoft Entra ID: quantas criar, como autenticar com o MFA obrigatório, exclusão do Acesso Condicional, alerta de uso com KQL e rotina de testes."
summary: "Como configurar, monitorar e testar contas de acesso de emergência no Entra ID seguindo a documentação da Microsoft, com consultas KQL para alertar sobre uso e alterações."
categories: ["Identidade"]
tags: ["entra id", "acesso condicional", "kql", "sentinel", "contas privilegiadas"]
series: ["Detecções com KQL"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0001", tecnica: "T1078.004", nome: "Cloud Accounts" }
  - { tatica: "TA0003", tecnica: "T1078.004", nome: "Cloud Accounts" }
---

Toda organização que usa o Microsoft Entra ID depende de alguém conseguir entrar como administrador. Quando o provedor de identidade federado cai, quando o único método de MFA dos administradores para de funcionar ou quando uma política de Acesso Condicional mal configurada bloqueia todo mundo, a saída é uma conta de acesso de emergência, também chamada de conta break-glass.

O problema é que essa conta tem o papel mais poderoso do tenant e quase nunca é usada. Para o atacante, é um alvo valioso: o MITRE ATT&CK descreve o abuso de contas legítimas de nuvem na técnica [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/), associada a acesso inicial, persistência, escalação de privilégio e furtividade. Este artigo resume as recomendações da página [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access) e mostra como transformar o uso dessas contas em alerta.

## Quando a conta de emergência faz falta

A documentação lista situações em que a organização pode perder o acesso administrativo:

- As contas de usuário são federadas e a federação fica indisponível, por falha de rede celular ou do provedor de identidade.
- Os administradores registraram o MFA só em métodos que deixaram de funcionar, como ligação ou SMS.
- A última pessoa com Global Administrator saiu da organização, ou a conta foi excluída ou desativada no ambiente local.
- Um desastre natural derruba redes móveis.
- Todas as atribuições de Global Administrator e Privileged Role Administrator são elegíveis no PIM, exigem aprovação e não há aprovadores. A página afirma que, nesse caso, a administração do tenant fica efetivamente travada.

## Como configurar

As recomendações principais da Microsoft são:

1. **Pelo menos duas contas**, para redundância.
2. **Contas somente na nuvem**, no domínio `*.onmicrosoft.com`, sem federação e sem sincronização do Active Directory local. O acesso de emergência da nuvem e o do ambiente local devem ser independentes um do outro.
3. **Global Administrator ativo e permanente.** No Privileged Identity Management, a atribuição deve ser ativa permanente, e não elegível. Uma conta que precisa ativar o papel depende justamente dos processos que podem estar quebrados na emergência.
4. **Sem vínculo com uma pessoa.** A conta não deve estar associada a um usuário específico nem a dispositivos pessoais, como o celular de um funcionário.
5. **Autenticação diferente da usada pelos outros administradores**, por exemplo uma chave de segurança FIDO2 exclusiva das contas de emergência. A credencial ou o dispositivo não pode expirar nem ser removido por limpeza automática de itens sem uso.
6. **Credenciais guardadas com segurança**, conhecidas só por quem está autorizado, em cofres à prova de fogo em locais separados. O uso deve partir de uma estação de trabalho segura, como uma Privileged Access Workstation.

<!-- Alessandro: acrescente aqui sua experiência com a guarda das chaves FIDO2 ou com o processo de custódia em clientes. -->

## O MFA obrigatório também vale para elas

Muitas organizações mantinham contas de emergência só com senha longa para escapar de qualquer dependência de MFA. Esse modelo não serve mais. A página do [MFA obrigatório do Azure e dos centros de administração](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication) diz que contas de emergência também precisam entrar com MFA quando a exigência começa a valer e que a regra se aplica a todas as contas, inclusive break-glass. A primeira fase cobre o portal do Azure, o centro de administração do Entra e o do Intune desde outubro de 2024, e o do Microsoft 365 desde fevereiro de 2025.

Para essas contas, a Microsoft recomenda dois métodos sem senha que atendem ao requisito:

- **Passkey (FIDO2)**, a opção recomendada.
- **Autenticação baseada em certificado**, se a organização já tem uma infraestrutura de chave pública.

## Acesso Condicional: excluir, mas com critério

A conta de emergência deve ficar fora de toda política de Acesso Condicional que bloqueie ou restrinja o login. A documentação explica o motivo: se ela estiver sujeita a exigências de MFA, de dispositivo em conformidade ou parecidas, pode ficar inutilizável justamente na emergência para a qual existe. Políticas em modo somente relatório não bloqueiam e não precisam de exclusão.

Na prática, a sugestão é criar um grupo dedicado, como `EmergencyAccess`, e excluí-lo das políticas de bloqueio ou restrição. A mesma página recomenda testar, por exemplo a cada trimestre, se as contas ainda conseguem entrar com a configuração atual de Acesso Condicional, e manter políticas de contingência prontas para ativar durante uma indisponibilidade.

## Monitoramento: todo uso vira alerta

Como a conta quase nunca é usada, qualquer login é um evento que precisa de explicação. A documentação orienta enviar os logs de login do Entra ao Azure Monitor e criar uma regra de alerta de pesquisa de logs personalizada sobre a tabela `SigninLogs`, filtrando pelo Object ID de cada conta, com limite estático "maior que 0" e severidade 0 (crítica). O exemplo oficial usa só `SigninLogs`. A versão abaixo é uma adaptação minha que inclui os logins não interativos e informa de qual tabela veio cada linha:

```kql
let BreakGlassIds = dynamic(["00aa00aa-bb11-cc22-dd33-44ee44ee44ee", "11bb11bb-cc22-dd33-ee44-55ff55ff55ff"]);
union withsource = SourceTable SigninLogs, AADNonInteractiveUserSignInLogs
| where UserId in (BreakGlassIds)
| project TimeGenerated, SourceTable, UserPrincipalName, UserId, AppDisplayName, IPAddress, ResultType
| order by TimeGenerated desc
```

Troque os identificadores de exemplo pelos Object IDs das suas contas, que aparecem em **Entra ID > Users**. Filtrar pelo Object ID, e não pelo UPN, evita que uma renomeação da conta quebre o alerta. Inclua tentativas que falharam: uma senha errada em uma conta de emergência também merece investigação. A mesma consulta funciona como regra analítica agendada no Microsoft Sentinel, que a documentação cita como alternativa ao Azure Monitor.

Além do login, vale saber quando alguém mexe nessas contas: troca de método de autenticação, remoção do papel, redefinição de senha ou exclusão. A consulta a seguir procura eventos do log de auditoria que têm uma das contas como alvo:

```kql
let BreakGlassIds = dynamic(["00aa00aa-bb11-cc22-dd33-44ee44ee44ee", "11bb11bb-cc22-dd33-ee44-55ff55ff55ff"]);
AuditLogs
| where TimeGenerated > ago(1d)
| mv-expand Target = TargetResources
| where tostring(Target.id) in (BreakGlassIds)
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, Category, Result, Actor, TargetUpn = tostring(Target.userPrincipalName)
| order by TimeGenerated desc
```

As colunas `TargetResources` e `InitiatedBy` são do tipo dinâmico, e os campos internos usados aqui (`id`, `userPrincipalName`, `displayName`) precisam ser conferidos nos seus próprios logs. A janela de um dia é um ponto de partida meu, não um valor oficial.

<!-- Alessandro: consultas não executadas em ambiente real. Valide os campos internos de TargetResources e InitiatedBy e o volume de alertas antes de transformar em regra agendada. -->

Quando o alerta disparar, a Microsoft recomenda preservar os logs do Entra e das cargas de trabalho, verificar se o uso foi um teste planejado, uma emergência real ou abuso, e revisar as ações executadas com a conta.

## Teste antes de precisar

Uma conta de emergência que nunca foi testada é uma aposta. A documentação pede validação pelo menos a cada 90 dias, sempre que a equipe de TI mudar e quando as assinaturas do Entra mudarem. A rotina mínima inclui:

- Avisar a equipe de monitoramento de segurança de que o teste está acontecendo.
- Revisar a lista de pessoas autorizadas e manter o processo documentado.
- Treinar administradores e responsáveis de segurança no procedimento.
- Confirmar que as contas entram e executam tarefas administrativas.
- Conferir que ninguém registrou MFA ou redefinição de senha em um dispositivo ou dado pessoal.
- Trocar as combinações dos cofres periodicamente e sempre que alguém com acesso sair da organização.

<!-- Alessandro: acrescente aqui como você organiza o teste trimestral e quem participa. -->

## Conclusão

A conta de emergência precisa estar disponível quando todo o resto falhar e, ao mesmo tempo, ser a conta mais vigiada do tenant. Isso significa duas contas somente na nuvem, Global Administrator ativo permanente, passkey FIDO2 ou certificado para cumprir o MFA obrigatório, exclusão consciente do Acesso Condicional, alerta crítico para qualquer login e teste a cada 90 dias. A consulta de login deste artigo também está na [biblioteca KQL]({{< relref "/kql" >}}) do site.

## Referências

- Microsoft Learn. [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- Microsoft Learn. [Planning for mandatory multifactor authentication for Azure and other admin portals](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication)
- MITRE ATT&CK. [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [AADNonInteractiveUserSignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- Microsoft Learn. [AuditLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
