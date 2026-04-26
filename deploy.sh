#!/bin/bash
set -e

MSG="${1:-deploy}"

git add -A
git commit -m "$MSG" 2>/dev/null || echo "[deploy] Nada novo para commitar."
git push origin main

tar czf - app.py crypto.py requirements.txt templates/ CLAUDE.md deploy.sh \
  | ssh vps "tar xzf - -C /home/orderapp/"
ssh vps "sudo systemctl restart orderapp"

echo "[deploy] Concluído."
