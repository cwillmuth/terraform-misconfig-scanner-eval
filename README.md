# Terraform Misconfig Scanner Eval

**Question:** How reliably does Checkov catch seeded AWS misconfigurations in Terraform?

We wrote Terraform for a small AWS environment with 10 seeded misconfigurations
(storage, IAM, networking) and 2 deliberately safe controls, scanned it with
Checkov, fixed the findings, and re-scanned. Everything runs locally. Terraform
is never applied.

**Authors:** Campbell Willmuth, Kass Gifford

## Status
Scan, fix, re-scan, and analysis complete. See [report.md](report.md).

## Headline results (Checkov 3.3.30)
- **Detection: 10/10** seeds flagged by an expected check (8/10 if the failure
  must be reported on the seed's own resource; see the report, section 3.2).
- **Misses: 0. False positives: 0** factual errors (6 findings on the controls,
  all explained in the report).
- **After the fixes:** seeded-check failures 15 to 0; all failed checks 67 to 42.

## Method
- `ground_truth.csv` is the answer key, committed before any scan. Only the
  `caught_before` and `caught_after` columns were filled in afterwards.
- A seed is **detected** if Checkov fails an expected check on the seed's own
  resource (*exact*) or on another resource in the same seed family
  (*linked*). A family is every resource labelled `seedNN_...`. We need the
  linked rule because Checkov reports CKV_AWS_20 and CKV_AWS_21 on the parent
  `aws_s3_bucket`, not on the ACL or versioning resource. Both rates are
  reported. The linked rule was added after the first scan; the report says so.
- A **false positive** is a failed check on a control that is wrong about what
  the config does. Correct but unrelated findings (logging, KMS, and so on) are
  classified as best-practice findings.
- `caught_before` = an expected check failed on the seed or its family.
  `caught_after` = an expected check still fails after the fix (goal: `no`).
- Every miss and false positive gets a written cause in `report.md`.

## Reproduce
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./run_eval.sh              # scan, re-scan, custom policy, score, print summary
./run_eval.sh --write-gt   # same, and fill caught_before / caught_after
```
This runs the two README commands below, plus the custom-policy scans and the
scorer:
```bash
checkov -d vulnerable/ --framework terraform -o json > results/checkov_vulnerable.json
checkov -d fixed/ --framework terraform -o json > results/checkov_fixed.json
```
Checkov exits with code 1 whenever it finds a failed check; that is expected.

## Layout
| Path | What it is |
|---|---|
| `vulnerable/main.tf` | 10 seeds + 2 controls (the "before") |
| `fixed/main.tf` | same labels, flaws corrected (the "after") |
| `custom_checks/` | OPTIONAL stretch goal: two custom Checkov policies (delete the folder to skip) |
| `ground_truth.csv` | answer key |
| `score.py` | scores scan output against the answer key |
| `check_seeds.py` | minimal vulnerable-only check: which seeds were detected |
| `run_eval.sh` | one-command rerun of the whole cycle |
| `results/` | raw Checkov JSON and `scorecard.json` / `scorecard.csv` |
| `report.md` | the write-up |

## Limitations
One scanner, one pinned version, one cloud, 10 seeds we chose ourselves, all
built around checks Checkov already has, using simple literal configuration (no
variables or modules). The detection rate describes this sample, not Checkov in
general. See the report, section 6.
