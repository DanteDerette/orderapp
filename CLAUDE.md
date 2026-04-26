# orderapp — Instruções para Claude Code

## Regra obrigatória após qualquer alteração no código

**Sempre que fizer qualquer mudança em arquivos do projeto**, executar na sequência:

1. Commit das alterações no git
2. Push para o GitHub (`DanteDerette/orderapp`, branch `main`)
3. Enviar arquivos para a VPS e reiniciar o serviço

### Comandos a executar

```bash
# 1. Commit e push
git add -A
git commit -m "<descrição da mudança>"
git push origin main

# 2. Enviar arquivos para VPS e reiniciar
# A VPS usa uWSGI — o diretório do app é /home/orderapp
# Não sobrescrever: orderapp.db, app.ini, wsgi.py, mysock.sock, .secret_key
tar czf - app.py crypto.py requirements.txt templates/ CLAUDE.md deploy.sh \
  | ssh vps "tar xzf - -C /home/orderapp/"
ssh vps "sudo systemctl restart orderapp"
```

## VPS

- Serviço: `orderapp.service` (uWSGI)
- Diretório: `/home/orderapp/`
- Alias SSH: `vps`
- Reiniciar: `ssh vps "sudo systemctl restart orderapp"`
- Arquivos exclusivos da VPS (não sobrescrever): `app.ini`, `wsgi.py`, `mysock.sock`, `orderapp.db`, `.secret_key`

## Repositório

- GitHub: https://github.com/DanteDerette/orderapp
- Branch principal: `main`

## Stack

- Python / Flask + uWSGI
- SQLite (`orderapp.db`)
- Templates Jinja2 em `templates/`
