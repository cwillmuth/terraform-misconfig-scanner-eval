#!/usr/bin/env bash
# One command to rerun the whole cycle: scan -> fix -> re-scan -> score.
#
#   ./run_eval.sh                  scan both folders, score, print the summary
#   ./run_eval.sh --write-gt       same, and also fill caught_before/caught_after
#                                  in ground_truth.csv
#
# Needs checkov on PATH, or in .venv/. Terraform is NEVER applied; Checkov only
# reads the .tf files as text and never contacts AWS.
set -uo pipefail
cd "$(dirname "$0")"

if [ -x .venv/bin/checkov ]; then CHECKOV=.venv/bin/checkov; else CHECKOV=${CHECKOV:-checkov}; fi
command -v "$CHECKOV" >/dev/null 2>&1 || [ -x "$CHECKOV" ] || {
  echo "checkov not found. Run: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 2
}

WRITE_GT=""
[ "${1:-}" = "--write-gt" ] && WRITE_GT="--write-ground-truth"

mkdir -p results
echo "Checkov: $($CHECKOV --version)"

# Checkov exits 1 whenever it finds a failed check, so a nonzero exit here is
# expected. Only exit codes above 1 mean a real error.
scan() {  # $1=folder  $2=output file  $3...=extra checkov args
  local dir=$1 out=$2; shift 2
  $CHECKOV -d "$dir" --framework terraform -o json "$@" > "$out" 2>/dev/null
  local rc=$?
  if [ $rc -gt 1 ]; then echo "checkov failed on $dir (exit $rc)" >&2; exit $rc; fi
}

echo "1/3 scan vulnerable/";  scan vulnerable results/checkov_vulnerable.json
echo "2/3 scan fixed/";       scan fixed      results/checkov_fixed.json

# Optional stretch goal: custom policies. Skipped if custom_checks/ is absent.
if [ -d custom_checks ]; then
  echo "    custom policies (custom_checks/)"
  scan vulnerable results/checkov_vulnerable_custom.json --external-checks-dir custom_checks --check CKV_TMSE_1,CKV_TMSE_2
  scan fixed      results/checkov_fixed_custom.json      --external-checks-dir custom_checks --check CKV_TMSE_1,CKV_TMSE_2
else
  rm -f results/checkov_vulnerable_custom.json results/checkov_fixed_custom.json
fi
echo "3/3 score"
python3 score.py $WRITE_GT
