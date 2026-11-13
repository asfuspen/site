---
title: "Regras de encaminhamento de e-mail: detecção, triagem e resposta no Exchange Online"
date: 2026-11-12
draft: false
description: "Como atacantes usam regras de caixa de entrada para desviar e esconder e-mails depois de comprometer uma conta, e como detectar, virar regra no Sentinel, investigar e responder."
summary: "Como atacantes usam regras de caixa de entrada para desviar e esconder e-mails, e como detectar, virar regra no Sentinel, investigar e responder."
categories: ["Detecção"]
tags: ["kql", "sentinel", "defender xdr", "exchange online", "e-mail"]
series: ["Detecções com KQL"]
nivel: "avancado"
featured: true
mitre:
  - { tatica: "TA0009", tecnica: "T1114.003", nome: "Email Forwarding Rule" }
  - { tatica: "TA0005", tecnica: "T1564.008", nome: "Email Hiding Rules" }
---

Depois de comprometer uma conta de e-mail, o atacante precisa de duas coisas: continuar lendo as mensagens e evitar que a vítima perceba. Regras de caixa de entrada resolvem as duas. O MITRE ATT&CK descreve o primeiro uso em [Email Forwarding Rule (T1114.003)](<https://attack.mitre.org/techniques/T1114/003/>) e o segundo em [Email Hiding Rules (T1564.008)](<https://attack.mitre.org/techniques/T1564/008/>).

O ponto que torna essa técnica perigosa está na página do T1114.003: a regra de encaminhamento permite manter acesso persistente aos e-mails da vítima mesmo depois de as credenciais comprometidas serem redefinidas pelos administradores. Trocar a senha não remove a regra.

Este artigo cobre o ciclo inteiro: onde o evento aparece, duas detecções em KQL para o Microsoft Sentinel, a consulta equivalente no Defender XDR, como transformar a detecção em regra agendada, a triagem, a resposta e a prevenção.

## Três formas de encaminhar

O [guia de classificação de alertas de encaminhamento](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-email-forwarding>) da Microsoft lista três mecanismos de encaminhamento automático:

| Mecanismo | Quem configura | Como aparece |
|---|---|---|
| Regra de caixa de entrada | O usuário, ou quem tem acesso à caixa | Operações `New-InboxRule`, `Set-InboxRule` e `UpdateInboxRules` |
| Encaminhamento SMTP da caixa | Administrador | `Set-Mailbox` com `ForwardingSmtpAddress` |
| Regra de transporte (ETR) | Administrador | `New-TransportRule` e `Set-TransportRule`, vale para a organização inteira |

A regra de transporte exige privilégio administrativo, mas o impacto é maior. O ATT&CK registra um caso em que o grupo LAPSUS$ criou uma regra de transporte no locatário para enviar todo o e-mail que entrava e saía da organização.

Nas regras de caixa de entrada, os parâmetros que interessam estão na documentação do [`New-InboxRule`](<https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboxrule>): `ForwardTo` encaminha a mensagem, `ForwardAsAttachmentTo` encaminha como anexo e `RedirectTo` redireciona. A [página de resposta a contas comprometidas](<https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account>) acrescenta um detalhe sobre o `RedirectTo`: as mensagens não são entregues na caixa original.

## Onde o evento aparece

A [lista de atividades do log de auditoria](<https://learn.microsoft.com/en-us/purview/audit-log-activities>) do Microsoft Purview distingue três operações, e a diferença entre elas muda a detecção:

- `New-InboxRule`: regra criada no Outlook na Web.
- `Set-InboxRule`: regra modificada no Outlook na Web.
- `UpdateInboxRules`: regra criada, modificada ou removida pelo cliente Outlook.

Uma consulta que procura só `New-InboxRule` não vê regras criadas pelo cliente Outlook.

No Microsoft Sentinel, esses eventos chegam na tabela [`OfficeActivity`](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity>). As colunas usadas aqui são `Operation`, `OfficeWorkload`, `Parameters` (nome e valor de todos os parâmetros usados no cmdlet), `UserId`, `ClientIP` e `ResultStatus`.

No Defender XDR, a tabela é [`CloudAppEvents`](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table>). Ela é preenchida pelo Microsoft Defender for Cloud Apps e só traz dados se o conector do Microsoft 365 estiver habilitado em Settings > Cloud apps > App connectors.

## Detecção 1: encaminhamento para fora da organização

A consulta abaixo extrai o destino do encaminhamento e mantém só os que ficam fora dos seus domínios. A técnica de transformar a coluna `Parameters` em propriedades vem da regra oficial [Multiple users email forwarded to same destination](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Office_MailForwarding.yaml>), do repositório Azure-Sentinel.

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

O que cada parte faz:

- `InternalDomains` precisa receber os domínios da sua organização. O guia da Microsoft manda validar se o destino não é um endereço interno ou um subdomínio da empresa, e é isso que o filtro final faz.
- `mv-apply` com `make_bag` converte a lista de parâmetros em um objeto, para ler `ForwardTo`, `RedirectTo`, `ForwardAsAttachmentTo` ou `ForwardingSmtpAddress` pelo nome.
- `trim_start(@"smtp:", ...)` remove o prefixo que o `ForwardingSmtpAddress` pode trazer. A regra oficial faz o mesmo.
- `mv-expand` separa regras com mais de um destinatário.

<!-- Alessandro: valide esta consulta no seu laboratório criando uma regra de teste para um endereço externo, e acrescente aqui o resultado com dados fictícios ou anonimizados. -->

## Detecção 2: regras que escondem mensagens

A segunda família não exfiltra nada. Ela impede que a vítima veja avisos. A página do T1564.008 diz que regras maliciosas costumam filtrar por palavras como `malware`, `suspicious`, `phish` e `hack` no assunto e no corpo, e mover ou apagar as mensagens.

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

A consulta retorna dois casos, os mesmos que o [guia de regras de manipulação](<https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules>) considera suspeitos:

- Regras com palavras de alerta no filtro. A lista `Keywords` é um subconjunto da usada na regra oficial [Malicious Inbox Rule](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Malicious_Inbox_Rule.yaml>). Adapte ao idioma da sua organização: se os avisos internos são em português, inclua termos em português.
- Regras sem filtro nenhum. O guia afirma que apagar todos os e-mails recebidos sem filtrar por palavra é indicador de atividade maliciosa.

Na triagem, olhe também a pasta de destino. A Microsoft cita Notes, Junk Email e RSS Subscriptions como destinos comuns, e a combinação de mover para uma pasta pouco visível e marcar como lida.

<!-- Alessandro: acrescente aqui um caso que você tenha investigado ou reproduzido em laboratório. -->

## A mesma busca no Defender XDR

Quem trabalha no portal do Defender pode usar a consulta que a própria Microsoft publica no guia de regras de manipulação. Ela inclui `UpdateInboxRules`, então cobre o cliente Outlook:

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

Duas observações antes de usar. O valor de `user_id` é o identificador da conta no Entra ID, não o e-mail. E a referência da tabela lista a coluna do provedor de internet como `Isp`, enquanto a consulta publicada escreve `ISP`. Se a consulta acusar coluna inexistente, esse é o primeiro lugar para olhar.

Os guias trazem ainda consultas de linha de base, que comparam a atividade da conta por provedor, país e agente de usuário nos 30 ou 60 dias anteriores ao alerta. Elas respondem se a regra foi criada de um lugar em que aquele usuário nunca esteve.

## Da consulta à regra agendada

Uma consulta que só roda quando alguém lembra não é detecção. No Sentinel, a [regra de análise agendada](<https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules>) tem quatro decisões que merecem atenção:

1. **Frequência e período.** "Run query every" define de quanto em quanto tempo a consulta roda e "Lookup data from the last" define o período coberto. Os dois aceitam de 5 minutos a 14 dias, e o período precisa ser maior ou igual à frequência. As duas regras oficiais citadas rodam uma vez por dia: a de encaminhamento olha 7 dias e a de regra maliciosa olha 1 dia.
2. **A coluna de tempo.** A documentação pede que a consulta retorne `TimeGenerated`, porque a regra usa essa coluna como referência do período. As duas consultas acima projetam essa coluna. Ao colar na regra, remova o filtro `ago(7d)` da consulta ou alinhe o valor ao período configurado.
3. **Mapeamento de entidades.** É o que liga o alerta à conta e ao IP no incidente. As regras oficiais mapeiam `UserId` para a entidade Account e o IP do cliente para a entidade IP. Um cuidado: as duas tratam o `ClientIP` antes de mapear, porque o valor pode vir com porta.
4. **Agrupamento.** Por padrão, a regra gera um único alerta por execução. Para este cenário, um alerta por evento facilita tratar cada caixa como um caso separado.

<!-- Alessandro: acrescente aqui as configurações que você usa em produção ou no laboratório, e o volume de alertas que observou. -->

## Triagem: é malicioso?

As perguntas vêm dos guias de classificação de alertas da Microsoft:

1. O destino é externo? Um endereço interno ou subdomínio da empresa muda a análise.
2. A regra tem filtro? Palavras ligadas a alertas de segurança pedem atenção, e a ausência total de filtro também é suspeita.
3. De onde a regra foi criada? Compare IP, provedor e país com o histórico do usuário.
4. Houve outros alertas para o usuário antes da criação da regra?
5. O mesmo IP aparece em outras atividades suspeitas no locatário?
6. O mesmo destino aparece em mais de uma caixa? Esse é exatamente o padrão que a regra oficial de encaminhamento procura.

## Resposta

A ordem abaixo segue a [página de resposta a contas comprometidas](<https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account>):

1. **Desabilitar a conta** até concluir a investigação. Se não for possível, redefinir a senha. A página avisa que senhas de aplicativo não são revogadas automaticamente na redefinição.
2. **Revogar as sessões ativas**, o que invalida o acesso em curso com as credenciais roubadas.
3. **Revisar os dispositivos de MFA** e remover os que o atacante tenha adicionado.
4. **Revisar os aplicativos com consentimento** do usuário.
5. **Revisar as funções administrativas** atribuídas à conta.
6. **Revisar os encaminhamentos** e remover os que forem suspeitos.

Para o passo 6, a página traz dois comandos. O primeiro mostra o encaminhamento configurado na caixa. Um valor preenchido em `ForwardingSmtpAddress` significa que o e-mail está sendo encaminhado para um destinatário externo.

```powershell
Get-Mailbox -Identity <Identity> | Format-List Forwarding*Address,DeliverTo*
```

O segundo lista as regras, incluindo as ocultas:

```powershell
Get-InboxRule -Mailbox <Identity> -IncludeHidden | Format-List Name,Enabled,RedirectTo,Forward*,Identity
```

O `-IncludeHidden` não é detalhe. O ATT&CK descreve atacantes que usam a MAPI para alterar as propriedades da regra e torná-la invisível no Outlook, no Outlook na Web e na maioria das ferramentas de administração do Exchange.

## Prevenção

O controle mais direto está na [política de spam de saída](<https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding>), que tem três valores para o encaminhamento externo automático:

- **Automatic - System-controlled:** é o padrão. A página explica que o comportamento pode variar entre organizações e recomenda configurar um valor explícito.
- **On:** o encaminhamento externo automático é permitido.
- **Off:** o encaminhamento externo automático é desabilitado, e o remetente recebe uma notificação de não entrega.

Com o valor Off, regras de caixa de entrada e encaminhamentos de caixa que redirecionam para endereços externos deixam de funcionar. O encaminhamento entre usuários internos não é afetado. A mensagem bloqueada volta com o código `5.7.520`.

O ATT&CK lista a mesma medida como mitigação M1042, além da auditoria periódica das regras (M1047).

## O que este artigo não cobre

- **Regras criadas pelo cliente Outlook no Sentinel.** As duas consultas para `OfficeActivity` filtram `New-InboxRule`, `Set-InboxRule` e `Set-Mailbox`. Operações `UpdateInboxRules` ficam de fora e precisam de tratamento próprio.
- **Regras de transporte.** A detecção de `New-TransportRule` e `Set-TransportRule` merece um artigo separado.
- **Detecções nativas do Defender for Cloud Apps.** A [página de políticas de anomalia](<https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy>) informa que as políticas legadas de encaminhamento suspeito e de manipulação de regras foram desabilitadas e migradas para um novo modelo. Confira o que está ativo no seu locatário antes de contar com elas.
- **Validação em ambiente real.** As consultas 1 e 2 foram escritas a partir da documentação e das regras oficiais, e ainda não foram executadas em um locatário.

## Conclusão

Regra de caixa de entrada é persistência barata: sobrevive à troca de senha, pode ser escondida e usa um recurso legítimo. A defesa tem três camadas. A prevenção desliga o encaminhamento externo automático. A detecção acompanha a criação e a alteração de regras, com atenção ao destino externo e às regras que apagam ou movem mensagens. A resposta remove a regra junto com a redefinição de credenciais, nunca só a senha.

O artigo anterior da série trata de [password spray]({{< relref "/posts/password-spray-kql-sentinel" >}}), uma das formas de chegar à conta que depois recebe essas regras.

## Referências

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
- Azure-Sentinel. [Multiple users email forwarded to same destination](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Office_MailForwarding.yaml>) e [Malicious Inbox Rule](<https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/Malicious_Inbox_Rule.yaml>)
