# Terraform Misconfig Scanner Eval

**Question:** How reliably does Checkov catch seeded AWS misconfigurations in Terraform?

We wrote Terraform for a small AWS environment with 10 seeded misconfigurations
(storage, IAM, networking) and 2 deliberately safe controls, scanned it with
Checkov, fixed the findings, and re-scanned. Everything runs locally. Terraform
is never applied.

**Authors:** Campbell Willmuth, Kass Gifford

## Status
Seeding baseline (in progress)

## Method
- `ground_truth.csv` is the answer key, committed before any scan.
- A seed is **detected** if Checkov fails a check on that resource that matches
  the flaw.
- A **false positive** is a failed check on a control that is not a real problem.
- Every miss and false positive gets a written cause in `report.md`.

## Reproduce
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
checkov -d vulnerable/ --framework terraform -o json > results/checkov_vulnerable.json
checkov -d fixed/ --framework terraform -o json > results/checkov_fixed.json
```

## Results
See [report.md](report.md).

## Limitations
One scanner, one pinned version, one cloud, 10 seeds we chose ourselves. The
detection rate describes this sample, not Checkov in general.