#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: curl -fsSL https://raw.githubusercontent.com/adiltech2432-bot/script-ken-net/main/install-remote.sh | sudo bash" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/script-ken-net.XXXXXX)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
ARCHIVE="${WORK_DIR}/source.zip"
EXTRACT_DIR="${WORK_DIR}/source"
mkdir -p "${EXTRACT_DIR}"

curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/adiltech2432-bot/script-ken-net/archive/refs/heads/main.zip" \
  --output "${ARCHIVE}"
python3 -m zipfile -e "${ARCHIVE}" "${EXTRACT_DIR}"

SOURCE_DIR="$(find "${EXTRACT_DIR}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
if [[ -z "${SOURCE_DIR}" || ! -f "${SOURCE_DIR}/install.sh" ]]; then
  echo "Could not find the project installer in the downloaded archive." >&2
  exit 1
fi
bash "${SOURCE_DIR}/install.sh"

