# orderapp — Instruções para Claude Code

## Regra obrigatória após qualquer alteração no código

**Sempre que fizer qualquer mudança em arquivos do projeto**, executar na sequência:

1. Commit das alterações no git
2. Push para o GitHub (`DanteDerette/orderapp`, branch `main`)
3. Reiniciar a aplicação na VPS via SSH

### Comandos a executar

```bash
# 1. Commit e push
git add -A
git commit -m "<descrição da mudança>"
git push origin main

# 2. Reiniciar na VPS
ssh vps "cd ~/orderapp && git pull origin main && sudo systemctl restart orderapp"
```

> Se o serviço na VPS tiver outro nome (ex: `gunicorn`, `orderapp.service`), ajustar o `systemctl restart` conforme necessário.

## Repositório

- GitHub: https://github.com/DanteDerette/orderapp
- Branch principal: `main`

## Stack

- Python / Flask
- SQLite (`orderapp.db`)
- Templates Jinja2 em `templates/`
