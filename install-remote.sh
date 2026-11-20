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

COMMIT_JSON="${WORK_DIR}/commit.json"
curl --fail --location --silent --show-error --retry 3 \
  --header 'Accept: application/vnd.github+json' \
  --header 'User-Agent: kennet-panel-installer' \
  "https://api.github.com/repos/adiltech2432-bot/script-ken-net/commits/main" \
  --output "${COMMIT_JSON}"
KENNET_BUILD_ID="$(python3 - "${COMMIT_JSON}" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["sha"])
PY
)"
if [[ ! "${KENNET_BUILD_ID}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "GitHub did not return a valid commit ID; refusing to install an unknown build." >&2
  exit 1
fi
echo "Downloading KEN-NET commit ${KENNET_BUILD_ID}"
curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/adiltech2432-bot/script-ken-net/archive/${KENNET_BUILD_ID}.zip" \
  --output "${ARCHIVE}"
python3 -m zipfile -e "${ARCHIVE}" "${EXTRACT_DIR}"

SOURCE_DIR="$(find "${EXTRACT_DIR}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
if [[ -z "${SOURCE_DIR}" || ! -f "${SOURCE_DIR}/install.sh" ]]; then
  echo "Could not find the project installer in the downloaded archive." >&2
  exit 1
fi
export KENNET_BUILD_ID
bash "${SOURCE_DIR}/install.sh"
