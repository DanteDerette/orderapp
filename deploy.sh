#!/bin/bash
set -e

MSG="${1:-deploy}"

git add -A
git commit -m "$MSG" 2>/dev/null || echo "[deploy] Nada novo para commitar."
git push origin main

ssh vps "cd ~/orderapp && git pull origin main && sudo systemctl restart orderapp"

echo "[deploy] Concluído."
