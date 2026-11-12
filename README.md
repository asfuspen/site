# Site pessoal de Alessandro Ferreira

Blog de cibersegurança feito com [Hugo](https://gohugo.io/) e design próprio. A publicação é automática pelo GitHub Pages a cada alteração na branch `main`.

## Estrutura

| Caminho | Conteúdo |
|---------|----------|
| `content/posts/` | Artigos do blog, um diretório por post com um `index.md` |
| `data/palestras.yaml` | Lista de palestras, lives e workshops |
| `data/projetos.yaml` | Lista de projetos e contribuições |
| `content/sobre/` | Página Sobre |
| `hugo.toml` | Configuração do site, menu, autor e redes sociais |
| `layouts/`, `assets/` | Modelos, estilos e scripts do design |
| `static/img/` | Imagens do site, como a foto de perfil |

## Escrever um post

```bash
hugo new content posts/meu-titulo/index.md
```

Edite o arquivo criado, troque `draft: true` por `draft: false` e envie para a `main`.

## Rodar localmente

Requer Hugo extended 0.165.

```bash
hugo server --buildDrafts
```

## Personalizar

- Nome, bio, foto, redes sociais e menu: `hugo.toml`
- Cores e fontes: variáveis no início de `assets/css/main.css`
- Domínio próprio: altere `baseURL` em `hugo.toml` e configure o domínio em Settings, Pages
