.PHONY: scan-vuln scan-fixed score

scan-vuln:
	checkov -d vulnerable/ -o json > results/vulnerable/checkov.json || true
	trivy config vulnerable/ -f json -o results/vulnerable/trivy.json

scan-fixed:
	checkov -d fixed/ -o json > results/fixed/checkov.json || true
	trivy config fixed/ -f json -o results/fixed/trivy.json

score:
	python scripts/score.py
