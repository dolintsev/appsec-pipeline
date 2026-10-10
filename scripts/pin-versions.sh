#!/usr/bin/env bash
# Закрепляет версии в .github/workflows/security.yml:
# actions — на хэш коммита, Docker-образы — на sha256-отпечаток, Semgrep — на номер версии.
# Запускать из корня репозитория: bash scripts/pin-versions.sh
set -euo pipefail
WF=.github/workflows/security.yml

# Хэш коммита, на который сейчас указывает тег (для аннотированных тегов берём строку ^{})
sha() {
  local out peeled
  out=$(git ls-remote "https://github.com/$1" "refs/tags/$2" "refs/tags/$2^{}")
  peeled=$(printf '%s\n' "$out" | awk '/\^\{\}$/ {print $1}')
  if [ -n "$peeled" ]; then echo "$peeled"; else printf '%s\n' "$out" | awk 'NR==1 {print $1}'; fi
}

# Отпечаток образа вида name@sha256:... (раннеры GitHub — linux/amd64)
digest() {
  docker pull -q --platform linux/amd64 "$1:latest" > /dev/null
  docker inspect --format '{{index .RepoDigests 0}}' "$1:latest"
}

CHECKOUT=$(sha actions/checkout v4)
UPLOAD=$(sha actions/upload-artifact v4)
CODEQL=$(sha github/codeql-action v3)
SEMGREP=$(curl -s https://pypi.org/pypi/semgrep/json | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])')
SYFT=$(digest anchore/syft)
TRIVY=$(digest aquasec/trivy)
NUCLEI=$(digest projectdiscovery/nuclei)
DASTARDLY=$(digest public.ecr.aws/portswigger/dastardly)

for v in CHECKOUT UPLOAD CODEQL SEMGREP SYFT TRIVY NUCLEI DASTARDLY; do
  [ -n "${!v}" ] || { echo "Не удалось получить $v"; exit 1; }
  printf '%-10s %s\n' "$v" "${!v}"
done

sed -i.bak \
  -e "s|PASTE_CHECKOUT_SHA|$CHECKOUT|g" \
  -e "s|PASTE_UPLOAD_ARTIFACT_SHA|$UPLOAD|g" \
  -e "s|PASTE_CODEQL_SHA|$CODEQL|g" \
  -e "s|PASTE_SEMGREP_VERSION|$SEMGREP|g" \
  -e "s|PASTE_SYFT_IMAGE|$SYFT|g" \
  -e "s|PASTE_TRIVY_IMAGE|$TRIVY|g" \
  -e "s|PASTE_NUCLEI_IMAGE|$NUCLEI|g" \
  -e "s|PASTE_DASTARDLY_IMAGE|$DASTARDLY|g" \
  "$WF"
rm -f "$WF.bak"

if grep -q PASTE_ "$WF"; then echo "Остались незаполненные места:"; grep -n PASTE_ "$WF"; exit 1; fi
echo "Готово: все версии закреплены в $WF"
