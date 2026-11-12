# Guia do repositório

Site pessoal de Alessandro Ferreira sobre cibersegurança, em português do Brasil. Hugo 0.165 extended com o tema Blowfish como módulo Hugo. O objetivo do conteúdo é construir um histórico de contribuições para o programa Microsoft MVP na categoria Security.

## Regras para posts

- Cada post fica em `content/posts/<slug>/index.md`, com slug em minúsculas, sem acentos e com hífens.
- Front matter obrigatório: `title`, `date`, `draft`, `description`, `summary`, `categories`, `tags`.
- Posts novos entram sempre por pull request, nunca direto na `main`. O Alessandro revisa e aprova antes de publicar.
- Escreva em português do Brasil, em tom técnico e direto, para profissionais de TI e segurança.
- Foco no ecossistema de segurança da Microsoft: Defender XDR, Sentinel, Entra ID, Purview, Intune, Azure. Temas gerais de segurança são bem-vindos quando têm aplicação prática.
- Estrutura sugerida: introdução com o problema, contexto, passo a passo ou análise, conclusão e referências.
- Toda afirmação factual precisa de fonte. Inclua a seção Referências com links para a documentação oficial (learn.microsoft.com) ou fontes primárias. Não invente comandos, cmdlets, nomes de tabelas, números de CVE nem estatísticas. Se não for possível confirmar algo, deixe fora.
- Não repita um tema que já existe em `content/posts/`.
- Blocos de código devem declarar a linguagem (`kql`, `powershell`, `bash`).
- Não escreva na primeira pessoa experiências que o Alessandro não teve. Deixe marcadores `<!-- Alessandro: acrescente aqui sua experiência -->` onde um relato pessoal enriqueceria o texto.

## Verificação

Antes de abrir um pull request, rode `hugo --gc --minify --buildDrafts` e confirme que o build passa.
