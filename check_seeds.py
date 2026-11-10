import csv, json

data = json.load(open("results/checkov_vulnerable.json"))
if isinstance(data, list):
    data = data[0]

# resource name -> set of check IDs that FAILED on it
failed = {}
for c in data["results"]["failed_checks"]:
    failed.setdefault(c["resource"], set()).add(c["check_id"])

print(data["summary"])
print()
for row in csv.DictReader(open("ground_truth.csv")):
    if not row["id"].startswith("SEED"):
        continue
    expected = set(row["expected_check"].split(";"))
    own = expected & failed.get(row["resource"], set())
    # same seed number, e.g. seed01_..., on any other resource (the parent bucket)
    prefix = "seed" + row["id"][-2:] + "_"
    other = {r: expected & ids for r, ids in failed.items()
             if r.split(".")[1].startswith(prefix) and r != row["resource"] and expected & ids}
    if own:
        verdict = "DETECTED on its own resource"
    elif other:
        verdict = "DETECTED on " + ", ".join(other)
    else:
        verdict = "MISSED"
    print(f"{row['id']}: {verdict}")
