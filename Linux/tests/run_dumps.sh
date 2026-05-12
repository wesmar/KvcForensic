#!/usr/bin/env bash
# Batch-process every minidump under ../../tmp and compare key facts
# (build, modules, memory ranges, secrets init, NT hashes) between Linux
# output and the Windows reference TXTs sitting next to each dump.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN="${ROOT}/linux-cli/kvcforensic-linux"
TEMPLATES="${ROOT}/linux-cli/resources/KvcForensic.json"
DUMP_DIR="${ROOT}/tmp"
OUT_DIR="${SCRIPT_DIR}/out"

mkdir -p "${OUT_DIR}"

if [[ ! -x "${BIN}" ]]; then
    echo "binary not built: ${BIN}" >&2
    exit 1
fi
if [[ ! -f "${TEMPLATES}" ]]; then
    echo "templates not found: ${TEMPLATES}" >&2
    exit 1
fi

shopt -s nullglob nocaseglob
DUMPS=(
    "${DUMP_DIR}"/*.dmp
    "${DUMP_DIR}"/forumowe/*.dmp
)
shopt -u nocaseglob
if [[ ${#DUMPS[@]} -eq 0 ]]; then
    echo "no dumps under ${DUMP_DIR}" >&2
    exit 1
fi

pass=0
fail=0
echo "DUMP                                    BUILD   MODULES  RANGES  SESSIONS  NT_HASHES  SECRETS"
echo "--------------------------------------- ------- -------- ------- --------- ---------- -------"

for dump in "${DUMPS[@]}"; do
    name="$(basename "${dump}" .dmp)"
    txt="${OUT_DIR}/${name}.txt"
    json="${OUT_DIR}/${name}.json"

    # Local regression run — reveal so the runner can grep NT hashes.
    if ! "${BIN}" --analyze-dump --input "${dump}" --output "${txt}" \
            --templates "${TEMPLATES}" --format both --full --reveal-secrets \
            >"${OUT_DIR}/${name}.log" 2>&1; then
        printf '%-39s ERR (see %s.log)\n' "${name}" "${name}"
        fail=$((fail + 1))
        continue
    fi

    build=$(awk '/^build_number/ {print $2; exit}' "${txt}")
    modules=$(awk '/^modules / {print $2; exit}' "${txt}")
    ranges=$(awk '/^memory64_ranges / {print $2; exit}' "${txt}")
    sessions=$(grep -cE '^luid ' "${txt}" || true)
    nt_hashes=$(grep -cE ' nt=[0-9a-f]{32}( |$)' "${txt}" || true)
    secrets=$(awk '/^lsa_secrets_init/ {print $2; exit}' "${txt}")

    printf '%-39s %-7s %-8s %-7s %-9s %-10s %-7s\n' \
        "${name}" "${build}" "${modules}" "${ranges}" "${sessions}" "${nt_hashes}" "${secrets}"
    pass=$((pass + 1))
done

echo
echo "summary: passed=${pass} failed=${fail}"
exit $((fail > 0 ? 1 : 0))
