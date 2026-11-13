---
title: "Como identificar password spray com KQL no Microsoft Sentinel"
date: 2026-11-12
draft: false
description: "O que é password spray, por que as proteções nativas do Entra ID não mostram as tentativas que falham e como encontrá-las nos logs de login com KQL."
summary: "O que é password spray, por que as proteções nativas não mostram as tentativas que falham e como encontrá-las nos logs de login com KQL."
categories: ["Detecção"]
tags: ["kql", "sentinel", "entra id", "identidade"]
nivel: "intermediario"
featured: true
mitre:
  - { tatica: "TA0006", tecnica: "T1110.003", nome: "Password Spraying" }
---

Em um ataque de password spray, o invasor testa uma senha comum, ou uma lista pequena de senhas, contra muitas contas diferentes. O MITRE ATT&CK cataloga a técnica como [T1110.003](https://attack.mitre.org/techniques/T1110/003/) e explica o motivo da escolha: as tentativas são distribuídas entre muitas contas para evitar o bloqueio que aconteceria ao insistir em uma única conta. A mesma página lembra que serviços de logon único e aplicativos em nuvem estão entre os alvos, e que o atacante pode reduzir o ritmo de propósito para não disparar alertas.

Este artigo mostra como procurar esse padrão na tabela `SigninLogs` do Microsoft Sentinel, o que a consulta enxerga e o que ela deixa passar.

## Por que as proteções nativas não bastam

O Entra ID já traz duas defesas que valem ser entendidas antes de escrever qualquer consulta.

**Bloqueio inteligente.** O [smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout) fica sempre ativo. Por padrão, a conta é bloqueada depois de 10 tentativas com falha em locatários do Azure Público, e o primeiro bloqueio dura um minuto. O contador é por conta. Um spray que tenta uma ou duas senhas em cada conta fica longe desse limite. O [guia de investigação da Microsoft](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray) chama isso de ataque "low and slow": os limites de bloqueio e de senha incorreta não chegam a ser atingidos.

**Detecção de risco.** O Microsoft Entra ID Protection tem uma [detecção chamada Password spray](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), que exige licença Microsoft Entra ID P2. A documentação é explícita sobre o alcance: a detecção só dispara quando o atacante valida a senha de um usuário com sucesso, e as tentativas de spray sem sucesso não geram detecção.

Ou seja, a fase em que o ataque ainda está falhando só aparece para quem consulta os logs de login.

## A consulta

A ideia é simples: um mesmo endereço IP falhando o login em muitas contas diferentes dentro de uma janela curta.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053")
| summarize Users = dcount(UserPrincipalName), Attempts = count()
    by IPAddress, bin(TimeGenerated, 1h)
| where Users >= 10
| order by Users desc
```

Linha por linha:

- `ResultType` é a coluna da [tabela SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) que guarda o código de erro do login. O valor `0` indica sucesso e os demais são falhas. A coluna é do tipo texto, por isso os códigos ficam entre aspas.
- `50126` é o erro de [usuário ou senha inválidos](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes). `50053` aparece quando a conta está bloqueada por excesso de tentativas, ou quando o login foi bloqueado por vir de um IP com atividade maliciosa.
- [`bin(TimeGenerated, 1h)`](https://learn.microsoft.com/en-us/kusto/query/bin-function) arredonda o horário para baixo em blocos de uma hora, para agrupar as tentativas por janela.
- [`dcount(UserPrincipalName)`](https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function) conta quantas contas diferentes cada IP tentou. A função devolve uma estimativa, troca precisão por desempenho e pode variar entre execuções. Para um limite como 10 isso não muda a conclusão, mas é bom saber.
- `Users >= 10` e a janela de uma hora são pontos de partida, não valores oficiais. Ajuste os dois ao volume do seu ambiente.

<!-- Alessandro: acrescente aqui o resultado da consulta no seu ambiente de laboratório, com dados fictícios ou anonimizados, e os limites que funcionaram para você. -->

## A senha foi descoberta?

Encontrar um IP suspeito responde só metade da pergunta. O guia da Microsoft separa dois desfechos:

- **Comprometimento de senha:** o atacante adivinhou a senha, mas não entrou na conta por causa de outros controles, como a autenticação multifator.
- **Comprometimento de conta:** o atacante adivinhou a senha e obteve acesso.

A segunda consulta parte dos IPs encontrados e procura logins que não terminaram em senha incorreta:

```kql
let SuspectIPs = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType in ("50126", "50053")
    | summarize Users = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
    | where Users >= 10
    | distinct IPAddress;
SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress in (SuspectIPs)
| where ResultType in ("0", "50074", "50076")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, AppDisplayName
| order by TimeGenerated asc
```

O valor `0` é um login concluído a partir de um IP que estava fazendo spray, o caso mais grave. Os códigos `50074` e `50076` indicam que o login parou na exigência de autenticação multifator: o guia de investigação lista o `50074` como "MFA required" e a referência de códigos descreve o `50076` como a exigência de MFA por uma política como o acesso condicional. Trate essas contas como candidatas a comprometimento de senha até confirmar o contrário.

<!-- Alessandro: confirme no seu ambiente como esses códigos aparecem quando a senha está correta e o MFA barra o acesso, e acrescente sua experiência com esse tipo de investigação. -->

## O que a consulta não enxerga

- **Spray distribuído.** A consulta agrupa por endereço IP. Um ataque que troca de IP a cada poucas tentativas não aparece. Nesse caso, vale agrupar por outras colunas da mesma tabela, como `UserAgent`, `Location` ou `AppDisplayName`.
- **Ritmo muito lento.** Se as tentativas forem espaçadas por mais de uma hora, cada janela terá poucas contas. Aumentar a janela do `bin` ajuda, ao custo de mais ruído.
- **Logins não interativos.** Eles ficam em outra tabela, [`AADNonInteractiveUserSignInLogs`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs), e a consulta acima não serve para ela sem adaptação. Lá, `ResultType` traz o resultado da operação e o código de erro fica em `ResultSignature`.
- **IPs legítimos compartilhados.** Antes de concluir que um IP é do atacante, confira se ele não é uma saída de rede da própria organização ou de um parceiro.

## Como responder

O guia de investigação da Microsoft recomenda, entre outras ações:

1. Trocar a senha de qualquer conta suspeita de comprometimento ou com senha descoberta.
2. Bloquear o endereço IP do atacante, com cuidado: o guia alerta que atacantes podem usar VPNs legítimas.
3. Bloquear a autenticação legada, se ela estiver em uso, avaliando o impacto no negócio.
4. Habilitar a autenticação multifator, se ainda não estiver habilitada.
5. Habilitar o Identity Protection para risco de usuário e de login.
6. Implementar a [proteção de senha](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad) com a lista personalizada de senhas proibidas. A lista global é aplicada automaticamente a todos os usuários do locatário, e a personalizada aceita até 1.000 termos.

O MITRE ATT&CK aponta três mitigações para a técnica: autenticação multifator (M1032), políticas de uso de conta com bloqueio após falhas (M1036) e políticas de senha (M1027).

## Conclusão

O password spray foi desenhado para ficar abaixo dos limites de bloqueio, e a detecção nativa de risco só avisa quando uma senha já foi validada. A consulta por IP com muitas contas em falha cobre o período anterior, e a segunda consulta diz quais contas precisam de atenção imediata. As duas estão na [biblioteca KQL]({{< relref "/kql" >}}) do site.

## Referências

- MITRE ATT&CK. [Brute Force: Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)
- Microsoft Learn. [Password spray investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray)
- Microsoft Learn. [Protect user accounts from attacks with Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- Microsoft Learn. [What are risk detections?](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)
- Microsoft Learn. [Eliminate bad passwords using Microsoft Entra Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad)
- Microsoft Learn. [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)
- Microsoft Learn. [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- Microsoft Learn. [AADNonInteractiveUserSignInLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- Microsoft Learn. [dcount() aggregation function](https://learn.microsoft.com/en-us/kusto/query/dcount-aggregation-function) e [bin() function](https://learn.microsoft.com/en-us/kusto/query/bin-function)
