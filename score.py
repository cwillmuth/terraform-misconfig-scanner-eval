#!/usr/bin/env python3
"""Score Checkov scan results against ground_truth.csv.

Inputs  (produced by run_eval.sh):
    results/checkov_vulnerable.json   stock Checkov, vulnerable/
    results/checkov_fixed.json        stock Checkov, fixed/
    results/checkov_vulnerable_custom.json   (optional) + custom_checks/
    results/checkov_fixed_custom.json        (optional) + custom_checks/

Outputs:
    results/scorecard.json   everything, machine readable
    results/scorecard.csv    one row per seed
    stdout                   a readable summary

    --write-ground-truth     also fills caught_before / caught_after in
                             ground_truth.csv. No other column is touched.

SCORING RULES (see README "Method")
    exact     an expected check FAILS on the seed's own resource.
    linked    no exact hit, but an expected check FAILS on another resource in
              the same seed family. A family is every resource whose label
              starts with "seedNN_" (so the supporting bucket for an ACL seed
              is in the family). Checkov reports some checks, notably
              CKV_AWS_20 and CKV_AWS_21, on the parent aws_s3_bucket instead of
              on the aws_s3_bucket_acl / aws_s3_bucket_versioning sub-resource.
    detected  exact OR linked. We report "exact only" separately so the effect
              of this attribution rule is visible and not hidden.
    after     "still flagged" = an expected check still FAILS on any resource
              in the seed family in fixed/. The goal is "no".
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
GT = ROOT / "ground_truth.csv"


def load(path):
    """Return (failed, passed, summary). failed/passed: {resource: {check ids}}."""
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):  # Checkov returns a list when several frameworks run
        data = data[0]
    failed, passed = defaultdict(set), defaultdict(set)
    for c in data["results"]["failed_checks"]:
        failed[c["resource"]].add(c["check_id"])
    for c in data["results"]["passed_checks"]:
        passed[c["resource"]].add(c["check_id"])
    return failed, passed, data["summary"]


def label(resource):
    """'aws_s3_bucket.seed01_public_acl' -> 'seed01_public_acl'"""
    return resource.split(".", 1)[1]


def family_of(seed_id):
    """'SEED-03' -> 'seed03_' ; 'CONTROL-01' -> 'control01_'"""
    kind, num = seed_id.split("-")
    return f"{kind.lower()}{num}_"


def family_resources(all_resources, seed_id):
    prefix = family_of(seed_id)
    return sorted(r for r in all_resources if label(r).startswith(prefix))


def read_gt():
    with open(GT, newline="") as f:
        return list(csv.DictReader(f))



# Findings that are NOT the seeded check but come from the same root flaw.
# This is a judgment call, made by reading each check's definition; it only
# affects the breakdown in report.md, never the detection rate.
CORROBORATING = {
    # CKV2_AWS_6 also requires block_public_acls and block_public_policy = true
    "SEED-02": {"CKV2_AWS_6"},
    # wildcard policy also trips the privilege-escalation / exfiltration checks
    "SEED-05": {"CKV2_AWS_40", "CKV_AWS_286", "CKV_AWS_287", "CKV_AWS_288",
                "CKV_AWS_289", "CKV_AWS_290"},
    # "all ports" also covers 22, 3389 and 80
    "SEED-09": {"CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260"},
}
# Supporting buckets for SEED-01..03 are missing the safeguards other seeds test.
SUPPORTING_BUCKET_GAP = {"CKV2_AWS_6", "CKV_AWS_21"}
UNATTACHED_SG = "CKV2_AWS_5"  # scan-only fixture never attaches a security group


def classify_findings(failed, gt_rows):
    """Split every failed check on vulnerable/ into a cause class."""
    expected = {r["id"]: {c for c in r["expected_check"].split(";") if c}
                for r in gt_rows if r["id"].startswith("SEED")}
    counts = defaultdict(int)
    for res, ids in failed.items():
        lab = label(res)
        for cid in ids:
            if lab.startswith("control"):
                k = "control"
            elif lab.startswith("seed"):
                sid = "SEED-" + lab[4:6]
                if cid in expected.get(sid, ()):
                    k = "expected"
                elif cid in CORROBORATING.get(sid, ()):
                    k = "corroborating"
                elif cid == UNATTACHED_SG:
                    k = "unattached_security_group"
                elif res.startswith("aws_s3_bucket.") and cid in SUPPORTING_BUCKET_GAP:
                    k = "supporting_bucket_gap"
                else:
                    k = "independent_best_practice"
            else:
                k = "other"
            counts[k] += 1
    return dict(counts)


def score(vuln, fixed):
    v_failed, v_passed, v_summary = vuln
    f_failed, f_passed, f_summary = fixed
    v_all = set(v_failed) | set(v_passed)
    f_all = set(f_failed) | set(f_passed)

    rows = []
    for row in read_gt():
        sid = row["id"]
        res = row["resource"]
        expected = [c for c in row["expected_check"].split(";") if c]
        fam = family_resources(v_all, sid)
        fam_after = family_resources(f_all, sid)

        if sid.startswith("SEED"):
            exact = sorted(set(expected) & v_failed.get(res, set()))
            linked_hits = {}
            for r in fam:
                if r == res:
                    continue
                hit = sorted(set(expected) & v_failed.get(r, set()))
                if hit:
                    linked_hits[r] = hit
            detected = bool(exact or linked_hits)
            still = {}
            for r in fam_after:
                hit = sorted(set(expected) & f_failed.get(r, set()))
                if hit:
                    still[r] = hit
            # every failed check on the family that is NOT an expected check
            unrelated_before = sorted(
                {c for r in fam for c in v_failed.get(r, set())} - set(expected))
            unrelated_after = sorted(
                {c for r in fam_after for c in f_failed.get(r, set())} - set(expected))
            rows.append({
                "id": sid, "resource": res, "category": row["category"],
                "flaw": row["flaw"],
                "expected_checks": expected,
                "exact_hits": exact,
                "linked_hits": linked_hits,
                "detected_exact": bool(exact),
                "detected_any": detected,
                "expected_fired": f"{len(set(exact) | {c for h in linked_hits.values() for c in h})}/{len(expected)}",
                "still_flagged_after": bool(still),
                "still_flagged_detail": still,
                "unrelated_findings_before": unrelated_before,
                "unrelated_findings_after": unrelated_after,
            })
        else:  # control
            ctl_before = {r: sorted(v_failed.get(r, set())) for r in fam if v_failed.get(r)}
            ctl_after = {r: sorted(f_failed.get(r, set())) for r in fam_after if f_failed.get(r)}
            rows.append({
                "id": sid, "resource": res, "category": row["category"],
                "flaw": row["flaw"], "control": True,
                "failed_checks_before": ctl_before,
                "failed_checks_after": ctl_after,
            })

    seeds = [r for r in rows if not r.get("control")]
    controls = [r for r in rows if r.get("control")]
    n = len(seeds)
    by_cat = defaultdict(lambda: {"seeds": 0, "exact": 0, "any": 0})
    for s in seeds:
        c = by_cat[s["category"]]
        c["seeds"] += 1
        c["exact"] += s["detected_exact"]
        c["any"] += s["detected_any"]

    # findings on the seeded issues themselves (expected checks only)
    def expected_fail_count(failed):
        total = 0
        for s in seeds:
            exp = set(s["expected_checks"])
            for r, ids in failed.items():
                if label(r).startswith(family_of(s["id"])):
                    total += len(exp & ids)
        return total

    summary = {
        "checkov_version_before": v_summary.get("checkov_version"),
        "seeds_total": n,
        "detected_exact": sum(s["detected_exact"] for s in seeds),
        "detected_any": sum(s["detected_any"] for s in seeds),
        "detection_rate_exact": round(sum(s["detected_exact"] for s in seeds) / n, 3),
        "detection_rate_any": round(sum(s["detected_any"] for s in seeds) / n, 3),
        "by_category": dict(by_cat),
        "total_failed_before": v_summary["failed"],
        "total_failed_after": f_summary["failed"],
        "total_passed_before": v_summary["passed"],
        "total_passed_after": f_summary["passed"],
        "expected_check_failures_before": expected_fail_count(v_failed),
        "expected_check_failures_after": expected_fail_count(f_failed),
        "seeds_still_flagged_after": sum(s["still_flagged_after"] for s in seeds),
        "seeds_fixed": sum(not s["still_flagged_after"] for s in seeds),
        "control_findings_before": sum(len(ids) for c in controls for ids in c["failed_checks_before"].values()),
        "control_findings_after": sum(len(ids) for c in controls for ids in c["failed_checks_after"].values()),
        "finding_classes_before": classify_findings(v_failed, read_gt()),
        "parsing_errors_before": v_summary.get("parsing_errors"),
        "parsing_errors_after": f_summary.get("parsing_errors"),
    }
    return rows, summary


def score_custom(path_v, path_f):
    """Check the custom policies. Only checks whose id starts with CKV_TMSE_."""
    if not (Path(path_v).exists() and Path(path_f).exists()):
        return None
    out = {}
    for tag, p in (("before", path_v), ("after", path_f)):
        failed, passed, _ = load(p)
        out[tag] = {
            "failed": {r: sorted(c for c in ids if c.startswith("CKV_TMSE_"))
                       for r, ids in failed.items()
                       if any(c.startswith("CKV_TMSE_") for c in ids)},
            "passed": {r: sorted(c for c in ids if c.startswith("CKV_TMSE_"))
                       for r, ids in passed.items()
                       if any(c.startswith("CKV_TMSE_") for c in ids)},
        }
    return out


def write_outputs(rows, summary, custom):
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "scorecard.json").write_text(
        json.dumps({"summary": summary, "rows": rows, "custom_policy": custom}, indent=2))
    with open(RESULTS / "scorecard.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "category", "flaw", "expected_checks", "expected_fired",
                    "detected_exact", "detected_any", "reported_on",
                    "still_flagged_after", "unrelated_findings_before"])
        for r in rows:
            if r.get("control"):
                continue
            reported_on = [r["resource"]] if r["exact_hits"] else []
            reported_on += list(r["linked_hits"])
            reported = ";".join(reported_on)
            w.writerow([r["id"], r["category"], r["flaw"], ";".join(r["expected_checks"]),
                        r["expected_fired"], r["detected_exact"], r["detected_any"], reported,
                        r["still_flagged_after"], len(r["unrelated_findings_before"])])


def fill_ground_truth(rows):
    """Fill caught_before / caught_after only. 'yes'/'no'.

    caught_before: expected check fails on the seed or its family (detected_any)
    caught_after : expected check STILL fails after the fix (we want 'no')
    """
    by_id = {r["id"]: r for r in rows if not r.get("control")}
    with open(GT, newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames
        data = list(reader)
    for d in data:
        r = by_id.get(d["id"])
        if r:
            d["caught_before"] = "yes" if r["detected_any"] else "no"
            d["caught_after"] = "yes" if r["still_flagged_after"] else "no"
        # controls keep their blank cells: they have no expected check
    with open(GT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(data)


def print_report(rows, s, custom):
    print("=" * 78)
    print(f"Checkov {s['checkov_version_before']}  |  seeds scored: {s['seeds_total']}")
    print("=" * 78)
    print(f"{'ID':8} {'cat':11} {'expected fired':15} {'exact':6} {'any':5} {'after':6}  reported on")
    for r in rows:
        if r.get("control"):
            continue
        where = r["resource"] if r["exact_hits"] else ", ".join(r["linked_hits"]) or "-"
        print(f"{r['id']:8} {r['category']:11} {r['expected_fired']:15} "
              f"{'yes' if r['detected_exact'] else 'NO':6} {'yes' if r['detected_any'] else 'NO':5} "
              f"{'still' if r['still_flagged_after'] else 'fixed':6}  {where}")
    print("-" * 78)
    print(f"Detection rate, exact resource only : {s['detected_exact']}/{s['seeds_total']} = {s['detection_rate_exact']:.0%}")
    print(f"Detection rate, incl. linked parent : {s['detected_any']}/{s['seeds_total']} = {s['detection_rate_any']:.0%}")
    for cat, c in s["by_category"].items():
        print(f"   {cat:11} exact {c['exact']}/{c['seeds']}   any {c['any']}/{c['seeds']}")
    print(f"Seeded-check failures before -> after : {s['expected_check_failures_before']} -> {s['expected_check_failures_after']}")
    print(f"Seeds no longer flagged after fix     : {s['seeds_fixed']}/{s['seeds_total']}")
    print(f"All failed checks before -> after     : {s['total_failed_before']} -> {s['total_failed_after']}")
    print(f"Findings on controls before -> after  : {s['control_findings_before']} -> {s['control_findings_after']}")
    fc = s["finding_classes_before"]
    print("Failed checks on vulnerable/ by cause    : " + ", ".join(f"{k} {v}" for k, v in sorted(fc.items())) + f"  (total {sum(fc.values())})")
    for r in rows:
        if r.get("control"):
            for res, ids in r["failed_checks_before"].items():
                print(f"   {r['id']} {res}: {', '.join(ids)}")
    if custom:
        print("-" * 78)
        print("Custom policy (CKV_TMSE_*)")
        for tag in ("before", "after"):
            for res, ids in custom[tag]["failed"].items():
                print(f"   {tag:6} FAIL {res}: {', '.join(ids)}")
            for res, ids in custom[tag]["passed"].items():
                print(f"   {tag:6} pass {res}: {', '.join(ids)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write-ground-truth", action="store_true",
                    help="fill caught_before / caught_after in ground_truth.csv")
    args = ap.parse_args()

    vuln = load(RESULTS / "checkov_vulnerable.json")
    fixed = load(RESULTS / "checkov_fixed.json")
    rows, summary = score(vuln, fixed)
    custom = score_custom(RESULTS / "checkov_vulnerable_custom.json",
                          RESULTS / "checkov_fixed_custom.json")
    write_outputs(rows, summary, custom)
    if args.write_ground_truth:
        fill_ground_truth(rows)
    print_report(rows, summary, custom)


if __name__ == "__main__":
    sys.exit(main())
