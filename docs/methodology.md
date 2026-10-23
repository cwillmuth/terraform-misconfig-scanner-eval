# Methodology

## Tool versions
- Checkov: (fill in with `checkov --version`)
- Trivy: (fill in with `trivy --version`)
- Terraform AWS provider constraint: see `vulnerable/main.tf`

## Definitions
- **Seed:** a deliberately planted misconfiguration, tagged `# SEED-NN` in the Terraform and listed in `ground_truth.csv`.
- **Control:** a deliberately safe resource, tagged `# CONTROL-NN`, used to measure false positives.
- **Detection (true positive):** a finding on the same resource as a seed whose check matches the seed's category.
- **Miss (false negative):** a seed with no matching finding.
- **False positive:** a finding on a control resource, or a finding that contradicts a correct configuration.
- **Unrelated finding:** a real issue on a seeded resource that is not the seeded flaw. Reported separately, not counted as detection.

## Scoring
- Detection rate = detected seeds / total seeds, per tool.
- False positive count = findings on controls, per tool.
- Before/after: compare findings on `vulnerable/` vs `fixed/`.

## Ground rules
1. `ground_truth.csv` is committed before any scan is run.
2. Expected check IDs come from scanner docs, not scan output.
3. Files in `results/` are raw tool output and are never edited.
