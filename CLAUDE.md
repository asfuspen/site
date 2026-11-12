# Guia do repositório

Site pessoal de Alessandro Ferreira sobre cibersegurança, em português do Brasil. Hugo 0.165 extended com design próprio, sem tema externo: os modelos ficam em `layouts/`, os estilos em `assets/css/main.css` e os scripts em `assets/js/main.js`. Palestras e projetos são listados a partir de `data/palestras.yaml` e `data/projetos.yaml`. O objetivo do conteúdo é construir um histórico de contribuições para o programa Microsoft MVP na categoria Security.

## Regras para posts

- Cada post fica em `content/posts/<slug>/index.md`, com slug em minúsculas, sem acentos e com hífens.
- Front matter obrigatório: `title`, `date`, `draft`, `description`, `summary`, `categories`, `tags`, `nivel` (`iniciante`, `intermediario` ou `avancado`). Opcionais: `mitre` para o mapa ATT&CK, no formato `- { tatica: "TA0006", tecnica: "T1110.003", nome: "Password Spraying" }` com identificadores e nomes oficiais conferidos em attack.mitre.org (a tática precisa existir em `data/mitre.yaml`, que segue a matriz atual de 15 táticas); `series: ["Nome da série"]` para posts em sequência e `featured: true` para destacar na página inicial.
- O site é bilíngue. Todo post tem a versão em português em `index.md` e a tradução em inglês em `index.en.md`, na mesma pasta, com o mesmo `date`, `nivel` e código. Traduza título, descrição, resumo, categorias, tags e texto.
- Consultas KQL reutilizáveis também entram em `data/kql.yaml` (campos `id`, `titulo`, `title_en`, `descricao`, `desc_en`, `produto`, `tabela`, `tags`, `mitre`, `query`). Só inclua tabelas e colunas confirmadas na documentação oficial.
- Posts novos entram sempre por pull request, nunca direto na `main`. O Alessandro revisa e aprova antes de publicar.
- Escreva em português do Brasil, em tom técnico e direto, para profissionais de TI e segurança.
- Foco no ecossistema de segurança da Microsoft: Defender XDR, Sentinel, Entra ID, Purview, Intune, Azure. Temas gerais de segurança são bem-vindos quando têm aplicação prática.
- Estrutura sugerida: introdução com o problema, contexto, passo a passo ou análise, conclusão e referências.
- Toda afirmação factual precisa de fonte. Inclua a seção Referências com links para a documentação oficial (learn.microsoft.com) ou fontes primárias. Não invente comandos, cmdlets, nomes de tabelas, números de CVE nem estatísticas. Se não for possível confirmar algo, deixe fora.
- Não repita um tema que já existe em `content/posts/`.
- Blocos de código devem declarar a linguagem (`kql`, `powershell`, `bash`).
- Textos da interface ficam em `i18n/pt-br.yaml` e `i18n/en.yaml`. Ao criar um texto novo em um modelo, adicione a chave nos dois arquivos.
- Não escreva na primeira pessoa experiências que o Alessandro não teve. Deixe marcadores `<!-- Alessandro: acrescente aqui sua experiência -->` onde um relato pessoal enriqueceria o texto.

## Verificação

Antes de abrir um pull request, rode `hugo --gc --minify --buildDrafts` e confirme que o build passa.
