---
title: "AD CS e o modelo de certificado mal configurado (ESC1): postura, detecção e correção"
date: 2026-11-14
draft: false
description: "Como um modelo de certificado do AD CS que aceita o nome informado pelo solicitante permite se passar por qualquer usuário do domínio, e como encontrar, detectar e corrigir com Defender for Identity, Defender XDR e Sentinel."
summary: "Como um modelo de certificado mal configurado no AD CS permite se passar por qualquer usuário, e como encontrar, detectar e corrigir."
categories: ["Detecção"]
tags: ["kql", "sentinel", "defender xdr", "defender for identity", "active directory", "ad cs"]
series: ["Detecções com KQL"]
nivel: "avancado"
mitre:
  - { tatica: "TA0006", tecnica: "T1649", nome: "Steal or Forge Authentication Certificates" }
---

No Active Directory, um certificado pode valer tanto quanto uma senha. A página do MITRE ATT&CK para [Steal or Forge Authentication Certificates (T1649)](<https://attack.mitre.org/techniques/T1649/>) afirma que os certificados do Active Directory Certificate Services (AD CS) são vinculados a uma identidade e podem ser usados como credenciais de contas de domínio. A mesma página explica que os valores de nome alternativo do titular (SAN) definem os nomes alternativos do dono do certificado, e que configurações incorretas podem permitir escalação de privilégio por meio das identidades associadas a um certificado.

O caso mais direto desse problema tem nome: ESC1. Ele foi descrito por Will Schroeder e Lee Christensen, da SpecterOps, no trabalho [Certified Pre-Owned](<https://specterops.io/blog/2021/06/17/certified-pre-owned/>), publicado em 17 de junho de 2021. A Microsoft resume o risco na [avaliação de postura de certificados](<https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>) do Defender for Identity: um modelo nessas condições permite que qualquer usuário sem privilégio assuma a identidade de um usuário arbitrário, incluindo um administrador de domínio.

Este artigo cobre o ciclo inteiro: as condições que tornam um modelo vulnerável, como encontrar esses modelos, quais alertas o Defender for Identity gera, onde os eventos aparecem no Defender XDR e no Sentinel, a correção e os limites do que foi escrito aqui.

## O que torna um modelo vulnerável

O texto da SpecterOps lista as condições do ESC1. Todas precisam estar presentes ao mesmo tempo:

| Condição | O que significa |
|---|---|
| A CA corporativa concede direito de inscrição a usuários de baixo privilégio | Qualquer usuário comum consegue pedir certificados a essa CA |
| A aprovação do gerente está desabilitada | O pedido é atendido sem revisão humana |
| Nenhuma assinatura autorizada é exigida | O pedido não precisa ser assinado por outro certificado |
| O descritor de segurança do modelo é permissivo demais | O modelo concede inscrição a usuários de baixo privilégio |
| O modelo define EKUs que habilitam autenticação | O certificado emitido serve para entrar no domínio |
| O modelo permite que o solicitante informe o SAN no pedido | Quem pede escolhe em nome de quem o certificado sai |

A última condição é a que dá nome ao problema. Segundo o texto, quando o sinalizador `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` está presente na propriedade `mspki-certificate-name-flag` do modelo, o solicitante pode especificar o SAN. No console de modelos de certificado (`certtmpl.msc`), essa opção aparece como "Supply in request".

Os EKUs que os autores apontam como suficientes para autenticação no domínio são:

- Client Authentication (`1.3.6.1.5.5.7.3.2`)
- PKINIT Client Authentication (`1.3.6.1.5.2.3.4`)
- Smart Card Logon (`1.3.6.1.4.1.311.20.2.2`)
- Any Purpose (`2.5.29.37.0`)
- Nenhum EKU (SubCA)

Sobre o EKU de PKINIT, o texto observa que ele não existe por padrão nas implantações do AD CS e precisa ser adicionado manualmente.

O resultado prático: um usuário comum pede um certificado com esse modelo, escreve no SAN o nome de um administrador e recebe um certificado válido para autenticar como esse administrador. Nenhuma senha foi roubada e nenhuma vulnerabilidade de software foi explorada. O ATT&CK registra que o grupo APT29 abusou de modelos de certificado mal configurados do AD CS.

<!-- Alessandro: se você já encontrou um modelo assim em auditoria ou em laboratório, descreva aqui como ele estava configurado, sem dados que identifiquem o ambiente. -->

## Como encontrar modelos vulneráveis

### Avaliação de postura do Defender for Identity

A [página de avaliações de certificados](<https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>) lista dez avaliações. A que trata deste artigo se chama "Prevent users to request a certificate valid for arbitrary users based on the certificate template (ESC1)" e está marcada como Preview. As demais cobrem outras variações descritas no mesmo trabalho da SpecterOps e em pesquisas posteriores:

| Avaliação | Código |
|---|---|
| Prevent users to request a certificate valid for arbitrary users based on the certificate template | ESC1 |
| Edit overly permissive certificate template with privileged EKU (Any purpose EKU or No EKU) | ESC2 |
| Edit misconfigured enrollment agent certificate template | ESC3 |
| Edit misconfigured certificate templates owner | ESC4 |
| Edit misconfigured certificate templates ACL | ESC4 |
| Edit vulnerable Certificate Authority setting | ESC6 |
| Edit misconfigured Certificate Authority ACL | ESC7 |
| Edit insecure ADCS certificate enrollment IIS endpoints | ESC8 |
| Enforce encryption for RPC certificate enrollment interface | ESC11 |
| Prevent Certificate Enrollment with arbitrary Application Policies | ESC15 |

Algumas dessas avaliações só ficam disponíveis para quem instalou um sensor em um servidor AD CS. A página traz esse aviso nas avaliações de ESC6, ESC8 e ESC15. Na seção do ESC1 o aviso não aparece.

### Revisão manual

Sem o Defender for Identity, a mitigação M1047 (Audit) do ATT&CK indica o caminho: verificar as permissões de inscrição e os modelos publicados com permissões excessivas, usando o console da autoridade certificadora (`certsrv.msc`) ou o `certutil.exe`. O que procurar em cada modelo publicado são as seis condições da tabela anterior.

<!-- Alessandro: acrescente aqui o comando ou o roteiro que você usa para listar os modelos publicados e as permissões, depois de validar no seu laboratório. Não incluí a sintaxe porque não a encontrei em uma página oficial que eu tenha conseguido abrir. -->

## O que o Defender for Identity alerta

A [lista de alertas XDR do Defender for Identity](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr>) tem um alerta específico para este cenário e outros que cobrem as etapas ao redor dele:

| Alerta | Severidade | Técnica | O que indica |
|---|---|---|---|
| Possible Active Directory Certificate Services enumeration | Média | T1649, T1087 | Atividade de enumeração do AD CS a partir de um endereço IP |
| Suspicious Active Directory Certificate Services (AD CS) misconfigured certificate template abuse (ESC1) | Alta | T1649 | Pedido de certificado com um modelo que permite ao solicitante informar valores arbitrários de SAN |
| Suspicious Active Directory Certificate Services (AD CS) certificate request | Alta | T1649 | Pedido de certificado ao AD CS com características anômalas |
| Suspicious Kerberos PKINIT authentication (AS-REQ) | Média | T1649, T1558 | Possível uso de um certificado não autorizado para autenticar como a conta afetada |
| Kerberos authentication following AD CS compromise | Alta | T1078.002, T1649 | Uma conta entrou via Kerberos com um certificado malicioso |

A ordem da tabela segue a ordem provável de um ataque: enumerar os modelos, pedir o certificado e usá-lo para autenticar. Essa leitura em sequência é interpretação minha, não uma afirmação da documentação.

A [lista de alertas clássicos](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic>) inclui o "Suspicious certificate usage over Kerberos protocol (PKINIT)", de identificador externo 2425 e severidade alta, com a observação de que ele só é suportado por sensores do Defender for Identity instalados no AD CS.

### O sensor no servidor AD CS

A [página de configuração de sensores para AD FS, AD CS e Entra Connect](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services>) traz três pontos que evitam surpresas:

- Não é preciso instalar sensores em servidores AD CS que ficam offline.
- No sensor v2.x, o suporte vale só para servidores AD CS com o serviço de função Certification Authority.
- O sensor v2.x no AD CS não pode usar a conta de serviço local para se conectar ao domínio. É preciso configurar uma conta de serviço de diretório.

## Habilitar a auditoria na CA

Sem auditoria, não há evento para o sensor nem para o Sentinel. A página [Configure Windows event auditing](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection>) pede duas configurações.

A primeira é a política de auditoria avançada, no caminho `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Object Access\Audit Certification Services`, com eventos de êxito e de falha habilitados.

A segunda é o filtro de auditoria da própria CA. A página dá os dois comandos:

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service certsvc
```

O serviço precisa ser reiniciado para a mudança valer. Pelo console, o caminho equivalente é abrir Certification Authority, clicar com o botão direito no nome da CA, escolher Properties e marcar os eventos na aba Auditing.

A página faz um alerta sobre um dos tipos de evento: auditar o início e a parada do serviço pode causar atraso na reinicialização quando o banco de dados do AD CS é grande. A orientação é remover entradas irrelevantes do banco ou não habilitar esse tipo específico.

Os eventos do AD CS que o Defender for Identity exige são estes:

| Evento | Descrição |
|---|---|
| 4870 | Certificate Services revoked a certificate |
| 4882 | The security permissions for Certificate Services changed |
| 4885 | The audit filter for Certificate Services changed |
| 4887 | Certificate Services approved a certificate request and issued a certificate |
| 4888 | Certificate Services denied a certificate request |
| 4890 | The certificate manager settings for Certificate Services changed |
| 4896 | One or more rows have been deleted from the certificate database |

O evento 4886 (Certificate Services received a certificate request) não está nessa lista, mas consta na página [Audit Certification Services](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services>) e é útil no Sentinel. Essa página estima o volume da subcategoria como baixo a médio em servidores que oferecem os serviços de função do AD CS.

## Busca no Defender XDR

Com o sensor instalado, a própria Microsoft indica a consulta de validação na página de configuração de sensores:

```kql
IdentityDirectoryEvents
| where Protocol == "Adcs"
```

Segundo a página, o resultado mostra emissões de certificado com êxito e com falha. A partir dela, uma visão por tipo de evento e por conta ajuda a conhecer o volume normal antes de procurar exceções. As colunas usadas estão na [referência da tabela](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table>):

```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where Protocol == "Adcs"
| summarize Events = count(), LastSeen = max(Timestamp) by ActionType, AccountUpn, DeviceName
| order by Events desc
```

Para olhar os eventos um a um, com os detalhes que o sensor registra:

```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where Protocol == "Adcs"
| project Timestamp, ActionType, AccountUpn, TargetAccountUpn, DeviceName, IPAddress, AdditionalFields
| order by Timestamp desc
```

Um limite importante: a referência da tabela não lista os valores de `ActionType` nem o conteúdo de `AdditionalFields` para eventos do AD CS. Ela remete à referência de esquema embutida no portal do Defender. Por isso as consultas acima não filtram por nome de modelo nem comparam o solicitante com o titular do certificado. Esse refinamento depende de ver os dados reais.

<!-- Alessandro: rode as duas consultas no seu ambiente e anote aqui quais valores de ActionType aparecem e quais campos de AdditionalFields trazem o modelo e o titular. Com isso dá para escrever o filtro que compara solicitante e titular. -->

## Busca no Microsoft Sentinel

No Sentinel, os eventos da CA chegam na tabela [`SecurityEvent`](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent>). Antes de escrever a consulta, confira o conjunto de eventos coletado. A página de [conjuntos de eventos de segurança do Windows](<https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference>) mostra que os eventos 4886, 4887 e 4888 fazem parte do conjunto Common e não fazem parte do conjunto Minimal. Um workspace que coleta só o conjunto Minimal não vê nenhum pedido de certificado.

A primeira consulta dá o volume diário por servidor:

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4886, 4887, 4888)
| summarize Requests = countif(EventID == 4886),
            Issued = countif(EventID == 4887),
            Denied = countif(EventID == 4888)
    by Computer, bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

A segunda traz os certificados emitidos com o conteúdo bruto do evento:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4887
| project TimeGenerated, Computer, Account, Activity, EventData
| order by TimeGenerated desc
```

As colunas `EventID`, `Computer`, `Account`, `Activity` e `EventData` constam na referência da tabela. O conteúdo de `EventData` para o evento 4887 não foi confirmado: a página de documentação desse evento não abriu durante a pesquisa. A tabela tem colunas com nome iniciado por `Template`, mas as descrições delas se referem a mensagens de evento e a modelos de GPO, não a modelos de certificado. Não use essas colunas para filtrar por modelo sem antes ver os dados.

<!-- Alessandro: valide as duas consultas no seu workspace e registre aqui os campos que aparecem em EventData no evento 4887. A detecção que interessa é o certificado emitido para um titular diferente de quem pediu. -->

## Correção

A avaliação de ESC1 do Defender for Identity lista cinco ações para um modelo vulnerável:

1. Desligar a configuração "Supply in the request".
2. Remover os EKUs que habilitam autenticação de usuário, como Client Authentication, Smartcard logon, PKINIT client authentication ou Any purpose.
3. Remover permissões de inscrição permissivas demais, que deixam qualquer usuário pedir certificado com aquele modelo.
4. Ligar a exigência de aprovação do gerente de certificados da CA.
5. Retirar o modelo da publicação em qualquer CA.

Cada ação quebra uma das condições da primeira tabela, e basta quebrar uma para o ESC1 deixar de existir. A escolha depende de quem usa o modelo hoje. Um cuidado meu, que não vem da documentação: antes de alterar, levante quais sistemas pedem certificados com ele, porque desligar o "Supply in the request" em um modelo usado por servidores web, por exemplo, interrompe a renovação desses certificados.

As mitigações do ATT&CK para o T1649 vão na mesma direção e acrescentam o contexto:

- **M1015, Active Directory Configuration:** tratar os servidores de CA como ativos de camada 0, considerar desabilitar o uso de SAN nas configurações de protocolo de autenticação e considerar exigir aprovação do gerente de certificados em modelos com SAN.
- **M1047, Audit:** revisar permissões de inscrição e modelos publicados.
- **M1042, Disable or Remove Feature or Program:** desabilitar protocolos antigos como NTLM e funções de inscrição web do AD CS que não sejam necessárias.
- **M1041, Encrypt Sensitive Information:** proteger certificados e chaves privadas, por exemplo com TPM ou HSM.

### Mapeamento forte de certificados

Uma proteção complementar veio pelo sistema operacional. O artigo [KB5014754](<https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16>) descreve mudanças na autenticação baseada em certificado nos controladores de domínio, ligadas às vulnerabilidades CVE-2022-34691, CVE-2022-26931 e CVE-2022-26923. A ideia é exigir um mapeamento forte entre o certificado e a conta. O artigo considera fortes os mapeamentos baseados em identificadores que não podem ser reutilizados.

Segundo o artigo, os controladores de domínio passam para o modo Full Enforcement com a atualização de segurança de fevereiro de 2025, e a autenticação é negada se o certificado não puder ser mapeado de forma forte. O modo de compatibilidade pôde ser restaurado até a atualização de 9 de setembro de 2025. Depois dela, a chave de registro `StrongCertificateBindingEnforcement` deixa de ser suportada.

O artigo também documenta eventos do KDC que ajudam na investigação, entre eles o de certificado sem mapeamento forte e o de SID do usuário diferente do SID do certificado. A numeração desses eventos varia conforme a versão do Windows Server. Consulte a tabela do próprio artigo para a sua versão.

Essa proteção não substitui a correção do modelo. Ela trata da forma como o controlador de domínio associa o certificado à conta. O modelo vulnerável continua sendo um erro de configuração que precisa ser corrigido na origem.

## Resposta a um incidente

Quando um alerta de ESC1 for confirmado, há uma diferença em relação a um incidente de senha: a autenticação descrita neste artigo usa o certificado, não a senha. Por isso a investigação precisa levantar os certificados emitidos no período, além de tratar as credenciais da conta. Essa recomendação é interpretação minha a partir do funcionamento da técnica. Não encontrei um roteiro oficial de resposta nas páginas consultadas.

<!-- Alessandro: acrescente aqui o seu roteiro de resposta, incluindo como você localiza e revoga os certificados emitidos durante o período do incidente. -->

## O que este artigo não cobre

- **As outras variações.** ESC2 a ESC15 têm condições e correções próprias. A página de avaliações do Defender for Identity é o melhor ponto de partida para cada uma.
- **Filtro por modelo e por titular.** As consultas mostram os eventos do AD CS, mas não isolam o pedido em nome de outra conta, porque os campos necessários não estão documentados nas páginas consultadas.
- **Regra de análise agendada.** Transformar a consulta em regra só faz sentido depois de conhecer os campos e o volume no ambiente real.
- **Validação em ambiente real.** Nenhuma das consultas foi executada em um locatário ou workspace.
- **A lista completa de recomendações da SpecterOps.** Os itens de prevenção e detecção estão no documento técnico completo dos autores, que não foi lido para este artigo.

## Conclusão

O ESC1 não depende de falha de software. Ele nasce de um modelo de certificado que reúne três permissões que, juntas, viram um atalho para qualquer identidade do domínio: inscrição aberta, EKU de autenticação e nome escolhido pelo solicitante. A defesa começa pela postura, com a revisão dos modelos publicados. Continua na auditoria da CA, sem a qual não existe evento para analisar. E termina na correção do modelo, lembrando que a autenticação por certificado não depende da senha da conta.

O artigo anterior da série trata de [regras de encaminhamento de e-mail]({{< relref "/posts/regras-encaminhamento-email-exchange-online" >}}), um caso em que redefinir a senha não encerra o acesso do atacante.

## Referências

- MITRE ATT&CK. [Steal or Forge Authentication Certificates (T1649)](<https://attack.mitre.org/techniques/T1649/>)
- SpecterOps. Will Schroeder e Lee Christensen. [Certified Pre-Owned](<https://specterops.io/blog/2021/06/17/certified-pre-owned/>), 17 de junho de 2021
- Microsoft Learn. [Security assessment: Certificates](<https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>)
- Microsoft Learn. [Microsoft Defender for Identity XDR security alerts](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr>)
- Microsoft Learn. [Microsoft Defender for Identity classic security alerts](<https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic>)
- Microsoft Learn. [Configure sensors for AD FS, AD CS, and Microsoft Entra Connect](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/active-directory-federation-services>)
- Microsoft Learn. [Configure Windows event auditing](<https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection>)
- Microsoft Learn. [Audit Certification Services](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services>)
- Microsoft Learn. [IdentityDirectoryEvents table](<https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table>)
- Microsoft Learn. [SecurityEvent table reference](<https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent>)
- Microsoft Learn. [Windows security event sets that can be sent to Microsoft Sentinel](<https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference>)
- Suporte da Microsoft. [KB5014754: Certificate-based authentication changes on Windows domain controllers](<https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16>)
