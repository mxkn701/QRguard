#!/usr/bin/env sh
# QRguard – instalace jedním příkazem: ./install.sh
set -e
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Chybí Node.js (verze 20 nebo novější)."
  echo "Stáhni ho z https://nodejs.org (verze LTS), nebo:"
  echo "  macOS:  brew install node"
  echo "  Linux:  použij správce balíčků své distribuce, např. sudo apt install nodejs npm"
  exit 1
fi

if [ ! -d node_modules/wrangler ]; then
  echo "→ Instaluji závislosti…"
  npm ci --no-audit --no-fund
fi

exec node scripts/setup.mjs "$@"
