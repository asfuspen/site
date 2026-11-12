# Site pessoal de Alessandro Ferreira

Blog de cibersegurança feito com [Hugo](https://gohugo.io/) e o tema [Blowfish](https://blowfish.page/). A publicação é automática pelo GitHub Pages a cada alteração na branch `main`.

## Estrutura

| Caminho | Conteúdo |
|---------|----------|
| `content/posts/` | Artigos do blog, um diretório por post com um `index.md` |
| `content/palestras/` | Palestras, lives e workshops |
| `content/projetos/` | Projetos e contribuições |
| `content/sobre/` | Página Sobre |
| `config/_default/` | Configuração do site, menu, autor e tema |
| `assets/img/` | Imagens do site, como a foto de perfil |

## Escrever um post

```bash
hugo new content posts/meu-titulo/index.md
```

Edite o arquivo criado, troque `draft: true` por `draft: false` e envie para a `main`.

## Rodar localmente

Requer Hugo extended 0.165 e Go.

```bash
hugo server --buildDrafts
```

## Personalizar

- Nome, bio, foto e redes sociais: `config/_default/languages.pt-br.toml`
- Cores e layout: `config/_default/params.toml`
- Menu: `config/_default/menus.pt-br.toml`
- Domínio próprio: altere `baseURL` em `config/_default/hugo.toml` e configure o domínio em Settings, Pages
