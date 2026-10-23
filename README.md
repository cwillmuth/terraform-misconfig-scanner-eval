# Terraform Misconfig Scanner Eval

**Question:** How reliably do open-source scanners (Checkov, Trivy) catch seeded AWS misconfigurations in Terraform?

I wrote Terraform for a small AWS environment with ~10 seeded misconfigurations, scanned it with Checkov and Trivy, fixed the findings, and re-scanned. Everything runs locally with no cloud account or spend.

## Status
Phase 1 of 4: seeding baseline (not started)

## Method (short)
TBD. See `docs/methodology.md`.

## Reproduce
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make scan-vuln
make scan-fixed
make score
```
No AWS account is needed. Terraform is never applied.

## Results
TBD

## Limitations
TBD

## Repo layout
- `ground_truth.csv`: answer key, committed before any scan
- `vulnerable/`: Terraform with seeded misconfigurations and safe controls
- `fixed/`: remediated Terraform
- `results/`: raw scanner output only, never hand-edited
- `scripts/score.py`: computes detection rate and false positives
- `report/`: interpreted findings
- `docs/`: methodology and decision log
