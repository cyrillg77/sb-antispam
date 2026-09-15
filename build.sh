#!/bin/bash
# Construit sb-antispam.zip avec le dossier sb-antispam/ à la racine (obligatoire pour WordPress)
set -e
cd "$(dirname "$0")"
V=$(grep -oP "^ \* Version: \K[0-9.]+" sb-antispam.php)
rm -rf build && mkdir -p build/sb-antispam
cp sb-antispam.php disposable-domains.txt build/sb-antispam/
(cd build && zip -qr ../sb-antispam.zip sb-antispam)
rm -rf build
sed -i "s/\"version\": \"[0-9.]*\"/\"version\": \"$V\"/" info.json
echo "sb-antispam.zip v$V prêt — info.json mis à jour. Crée la release v$V et attache le zip."
