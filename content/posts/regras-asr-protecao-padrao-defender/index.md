---
title: "Regras ASR de proteção padrão: do modo auditoria ao bloqueio no Defender for Endpoint"
date: 2026-11-14
draft: false
description: "Como ativar as três regras de redução da superfície de ataque (ASR) que a Microsoft classifica como proteção padrão, testar o restante em modo auditoria e acompanhar os eventos com KQL no Defender XDR."
summary: "As três regras ASR de proteção padrão, como testar as demais em modo auditoria e como medir o impacto com KQL no Defender XDR antes de bloquear."
categories: ["Endpoint"]
tags: ["defender for endpoint", "defender xdr", "asr", "kql", "powershell", "hardening"]
nivel: "intermediario"
mitre:
  - { tatica: "TA0006", tecnica: "T1003.001", nome: "LSASS Memory" }
  - { tatica: "TA0003", tecnica: "T1546.003", nome: "Windows Management Instrumentation Event Subscription" }
---

As regras de redução da superfície de ataque (ASR, na sigla em inglês) do Microsoft Defender for Endpoint bloqueiam comportamentos que malware e atacantes usam com frequência: um documento do Office que abre um processo filho, um script ofuscado, um processo que tenta ler a memória do LSASS. O problema é que alguns desses comportamentos também podem aparecer em software legítimo, como macros, ferramentas de gestão e instaladores internos. Ativar tudo em bloqueio de uma vez arrisca interromper esses aplicativos.

A própria Microsoft propõe um caminho mais seguro: ativar já as regras de baixo risco e testar as demais em modo auditoria antes de bloquear. Este artigo mostra esse caminho com os cmdlets e a consulta que constam na documentação oficial.

## Pré-requisitos

Segundo a [visão geral das regras ASR](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview), as regras funcionam nas edições Pro e Enterprise do Windows 10 ou posterior, no Windows Server 2012 R2 ou posterior e no Azure Local 23H2 ou posterior. O Microsoft Defender Antivirus precisa ser o antivírus ativo, com proteção em tempo real e proteção entregue pela nuvem ligadas; o Defender não pode estar em modo passivo nem desligado.

Sobre licença, a página diz que as regras não exigem o Microsoft 365 E5, mas que os recursos avançados de gestão, como monitoramento, relatórios e configuração no portal do Defender XDR, não estão disponíveis com outras licenças, citando como exemplos o Windows Pro e o Microsoft 365 E3.

## Os modos de cada regra

Cada regra é configurada por GUID e recebe um modo. A página [Enable attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure) lista os valores aceitos pelo parâmetro `AttackSurfaceReductionRules_Actions`:

| Valor | Nome | Efeito |
| --- | --- | --- |
| `0` | `Disabled` | Regra desligada |
| `1` | `Enabled` | Bloqueio |
| `2` | `AuditMode` | Só registra o evento |
| `5` | `NotConfigured` | Não configurada |
| `6` | `Warn` | Bloqueia, mas o usuário pode desbloquear |

No modo Warn, a regra age como em bloqueio, mas o usuário pode clicar em **Unblock** na notificação e liberar a ação por 24 horas. A visão geral informa que esse modo exige Windows 10 1809 ou posterior, não está disponível no Configuration Manager e não é suportado por duas regras: a de roubo de credenciais do LSASS e a que impede aplicativos do Office de injetar código em outros processos.

## Passo 1: ativar as regras de proteção padrão

A [referência das regras ASR](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) separa três regras sob o título "Standard protection rules". O [guia de teste da implantação](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test) diz que, em geral, essas regras podem ser ativadas em bloqueio ou Warn sem teste prévio.

| Regra | GUID |
| --- | --- |
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block credential stealing from the Windows local security authority subsystem | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |

Dois detalhes da referência ajudam a entender o alcance. A regra de drivers impede que aplicativos gravem drivers assinados vulneráveis no computador, mas não impede o carregamento de drivers que já estão lá. A regra do LSASS, que protege contra o roubo de credenciais da memória do processo (técnica [T1003.001](https://attack.mitre.org/techniques/T1003/001/) do MITRE ATT&CK), não é necessária quando a proteção LSA já está ativada. A regra de WMI trata a persistência por assinatura de eventos WMI, a técnica [T1546.003](https://attack.mitre.org/techniques/T1546/003/).

Em um computador de teste, o PowerShell aplica as três regras em bloqueio sem apagar as demais:

```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled
```

A documentação faz dois alertas importantes. Primeiro, `Set-MpPreference` sobrescreve todas as regras já configuradas, enquanto `Add-MpPreference` e `Remove-MpPreference` mexem só nas regras informadas. Segundo, a configuração local tem a menor precedência: qualquer política aplicada por Intune, Configuration Manager ou GPO a substitui na inicialização. Em produção, portanto, a configuração deve vir da ferramenta de gestão que você já usa; o PowerShell serve para laboratório e conferência.

Para ver o que está aplicado em um dispositivo, a página traz este comando:

```powershell
$p = Get-MpPreference;0..([math]::Min($p.AttackSurfaceReductionRules_Ids.Count,$p.AttackSurfaceReductionRules_Actions.Count)-1) | % {[pscustomobject]@{Id=$p.AttackSurfaceReductionRules_Ids[$_];Action=$p.AttackSurfaceReductionRules_Actions[$_]}} | Format-Table -AutoSize
```

Um cuidado ao copiar exemplos: no exemplo de `Set-MpPreference` da página de configuração, o GUID da regra de WMI aparece sem o último caractere (`...636979351e5`). O GUID completo, como na referência, termina em `351e5b`.

## Passo 2: auditar as demais regras em um grupo piloto

Para as outras regras, o guia de teste recomenda começar por um anel inicial pequeno de dispositivos e, normalmente, ativar todas as regras em modo auditoria ao mesmo tempo. Os passos do guia são: testar em auditoria, revisar os dados e avaliar o impacto, e então configurar as exclusões necessárias.

<!-- Alessandro: acrescente aqui sua experiência com o tamanho do grupo piloto e o tempo de auditoria que costuma usar. -->

## Passo 3: medir o impacto com KQL

No modo auditoria, nada é bloqueado, mas cada ocorrência vira evento. A visão geral das regras indica a consulta de partida no Advanced Hunting do Defender XDR:

```kql
DeviceEvents
| where ActionType startswith "Asr"
| where ActionType endswith "Audited"
```

Para decidir regra por regra, é mais útil agrupar por regra e pelo processo que disparou o evento. As colunas abaixo constam no [esquema da tabela DeviceEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table):

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Asr" and ActionType endswith "Audited"
| summarize Events = count(), Devices = dcount(DeviceName),
    SampleFiles = make_set(FileName, 5), SampleFolders = make_set(FolderPath, 5)
    by ActionType, InitiatingProcessFileName
| order by Events desc
```

<!-- Alessandro: consulta não executada em ambiente real. Valide o resultado e ajuste a janela à retenção do seu tenant. -->

A janela de 30 dias é um ponto de partida meu, não um valor oficial. Uma regra com poucos eventos, todos de processos que você não reconhece, é candidata a bloqueio. Uma regra que dispara centenas de vezes a partir de um aplicativo de negócio precisa de exclusão ou de conversa com o dono do aplicativo antes. Fora do portal, o guia de teste aponta o evento 1122 no log **Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational** para regras em auditoria.

As mesmas consultas servem depois do bloqueio: basta trocar `Audited` por `Blocked`. Na regra do LSASS, por exemplo, a referência lista os tipos `AsrLsassCredentialTheftAudited` e `AsrLsassCredentialTheftBlocked`.

## Passo 4: exclusões com critério

Quando um aplicativo legítimo dispara uma regra, a exclusão por caminho é feita com `AttackSurfaceReductionOnlyExclusions`. Seguindo a sintaxe documentada:

```powershell
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Data\LOBApp\app1.exe"
```

Como recomendação prática, e não regra da documentação, prefira o caminho do executável a uma pasta inteira e registre o motivo de cada exclusão: tudo o que fica excluído deixa de ser avaliado pelas regras ASR. Para conferir as exclusões aplicadas, use `(Get-MpPreference).AttackSurfaceReductionOnlyExclusions`.

## Conclusão

As três regras de proteção padrão tratam roubo de credenciais do LSASS, persistência por WMI e abuso de drivers vulneráveis, e a Microsoft indica que em geral podem entrar em bloqueio sem teste prévio. O restante pede método: auditoria em um grupo piloto, análise dos eventos com KQL, exclusões pontuais e bloqueio por anéis. A consulta de impacto deste artigo também está na [biblioteca KQL]({{< relref "/kql" >}}) do site.

## Referências

- Microsoft Learn. [Attack surface reduction rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- Microsoft Learn. [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- Microsoft Learn. [Test attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test)
- Microsoft Learn. [Enable attack surface reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure)
- Microsoft Learn. [DeviceEvents table in the advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- MITRE ATT&CK. [OS Credential Dumping: LSASS Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001/)
- MITRE ATT&CK. [Event Triggered Execution: Windows Management Instrumentation Event Subscription (T1546.003)](https://attack.mitre.org/techniques/T1546/003/)
