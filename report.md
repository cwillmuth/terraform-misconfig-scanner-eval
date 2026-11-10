# Report: How reliably does Checkov catch seeded AWS misconfigurations?

**Authors:** Campbell Willmuth, Kass Gifford
**Scanner:** Checkov 3.3.30 (pinned in `requirements.txt`), `--framework terraform`
**Everything is reproducible with one command:** `./run_eval.sh` (see [Reproduce](#reproduce)).
Raw scanner output is in `results/`; the scored tables are in `results/scorecard.json` and `results/scorecard.csv`.

## 1. Summary

| Metric | Result |
|---|---|
| Seeded misconfigurations | 10 (4 storage, 3 IAM, 3 networking) + 2 controls |
| **Detection rate, expected check fails on the seed or its linked parent resource** | **10 / 10 (100%)** |
| **Detection rate, expected check fails on the seed's own resource only** | **8 / 10 (80%)** |
| Expected checks that fired | 15 of 15 |
| Misses (seed not flagged by any expected check) | 0 |
| Misses by category | Storage 0, IAM 0, networking 0 |
| False positives on the controls | 0 factual errors; 6 findings, all explained (5 best-practice, 1 test-fixture artifact) |
| Seeded-check failures, before fix to after fix | 15 to 0 |
| Seeds no longer flagged after the fix | 10 / 10 |
| All failed checks, before to after | 67 to 42 |
| Custom policy | 2 written (CKV_TMSE_1, CKV_TMSE_2); both fail on the exact seed resource and pass after the fix |

**How to read the two detection rates.** Two of the ten seeds (SEED-01 and SEED-03) were caught by the expected check, but Checkov reported the failure on the parent `aws_s3_bucket`, not on the `aws_s3_bucket_acl` / `aws_s3_bucket_versioning` resource we planted the flaw in. A literal reading of "fails a check on *that resource*" scores them as misses (8/10). Both are real detections of the right flaw (10/10). Section 3.2 explains why this happens. We report both numbers so the reader can choose; we do not think either one alone tells the whole story.

**What this does not show.** 100% on 10 simple, textbook seeds that we chose is not Checkov's real-world detection rate. See [Limitations](#6-limitations).

## 2. Method

The answer key (`ground_truth.csv`: resource, flaw, category, expected check IDs) was committed before any scan. Only its two empty result columns were filled in afterwards; no expected check, resource, or flaw was edited. This was verified by comparing the file against its original.

- `vulnerable/main.tf`: 10 seeds, each isolating one flaw, plus 2 controls.
- `fixed/main.tf`: same resource labels, each flaw corrected. `diff vulnerable/main.tf fixed/main.tf` shows exactly what changed. SEED-06 is the one exception: the flaw is the *type* of attachment (user policy), so the fix replaces `aws_iam_user_policy` with `aws_iam_group_policy` and adds a group and a membership.
- Both folders were scanned with the README command. Checkov parsed both with **0 parsing errors**.

**Scoring rules** (implemented in `score.py`):

- **Exact detection:** an expected check FAILS on the seed's own resource.
- **Linked detection:** an expected check FAILS on another resource in the same seed family. A family is every resource whose label starts with `seedNN_`, which pulls in the supporting bucket of an ACL or versioning seed.
- **Detected** = exact or linked. Seeds with several expected checks (SEED-02, SEED-05) count as detected if any one fires; the number that fired is recorded.
- **After the fix, "still flagged"** = an expected check still fails on any resource in the seed family.
- A **false positive** is a failed check on a control that is wrong about what the config does. Findings on controls that are correct but unrelated to the seeded category are classified separately as best-practice findings.

> **Disclosure.** The linked-detection rule was added after the first scan, when SEED-01 and SEED-03 first appeared to be misses. The exact-only number (8/10) is the unmodified reading of the original rule, which is why it is reported next to the 10/10 figure.

## 3. Results

### 3.1 Detection by seed

| Seed | Category | Flaw | Expected checks | Fired | Reported on | After fix |
|---|---|---|---|---|---|---|
| SEED-01 | storage | S3 ACL grants public read | CKV_AWS_20 | 1/1 | **parent bucket** `aws_s3_bucket.seed01_public_acl` | cleared |
| SEED-02 | storage | Public access block disabled | CKV_AWS_53, 54, 55, 56 | **4/4** | `aws_s3_bucket_public_access_block.seed02_no_pab` | cleared |
| SEED-03 | storage | S3 versioning suspended | CKV_AWS_21 | 1/1 | **parent bucket** `aws_s3_bucket.seed03_no_versioning` | cleared |
| SEED-04 | storage | RDS storage not encrypted | CKV_AWS_16 | 1/1 | `aws_db_instance.seed04_unencrypted_db` | cleared |
| SEED-05 | iam | IAM policy allows `*` on `*` | CKV_AWS_62, 63, 355 | **3/3** | `aws_iam_policy.seed05_wildcard` | cleared |
| SEED-06 | iam | Policy attached to a user | CKV_AWS_40 | 1/1 | `aws_iam_user_policy.seed06_user_inline` | cleared |
| SEED-07 | iam | Password minimum length 6 | CKV_AWS_10 | 1/1 | `aws_iam_account_password_policy.seed07_weak` | cleared |
| SEED-08 | networking | SSH open to 0.0.0.0/0 | CKV_AWS_24 | 1/1 | `aws_security_group.seed08_ssh_open` | cleared |
| SEED-09 | networking | All ports open to 0.0.0.0/0 | CKV_AWS_277 | 1/1 | `aws_security_group.seed09_all_ports_open` | cleared |
| SEED-10 | networking | RDS publicly accessible | CKV_AWS_17 | 1/1 | `aws_db_instance.seed10_public_db` | cleared |

By category (any / exact-resource): storage 4/4 (2/4), IAM 3/3 (3/3), networking 3/3 (3/3).

### 3.2 The two attribution cases (SEED-01, SEED-03) and their cause

Strictly, these are the only "misses" in the study, and they are misses of *location*, not of *detection*.

**Cause (verified in the installed Checkov 3.3.30 source).** CKV_AWS_20 and CKV_AWS_21 are graph checks declared on `resource_types: ["aws_s3_bucket"]`. They follow a connection from the bucket to its `aws_s3_bucket_acl` or `aws_s3_bucket_versioning` sibling and evaluate that sibling's value. Since the check belongs to the bucket, Checkov always reports its result on the bucket. This follows from how the AWS provider split bucket settings into separate resources, and it is how the check is written, not a parsing failure.

**Evidence the checks respond to the seeded value and not just to the bucket:**

- CKV_AWS_20 fails only on the one bucket whose ACL is `public-read` and passes on the other three buckets that have no public ACL. After the fix (`acl = "private"`) it passes.
- CKV_AWS_21 fails on the bucket whose versioning is `Suspended`, passes on CONTROL-01 (`Enabled`), and passes on SEED-03's bucket after the fix (`Enabled`).

**Two further observations:**

1. **No stock check on the ACL resource itself evaluates `acl = "public-read"`.** The two checks that do target `aws_s3_bucket_acl` (CKV_AWS_375, CKV2_AWS_43) only inspect explicit `access_control_policy` grant blocks, so both passed on SEED-01. The bucket-level CKV_AWS_20 is the only stock check that catches a canned public ACL in this layout.
2. **CKV_AWS_21 cannot tell "Suspended" from "no versioning resource at all".** It also fails on the SEED-01 and SEED-02 buckets, which have no versioning resource. The check is binary: Enabled passes, anything else fails.

**Mitigation: custom policy (stretch goal).** `custom_checks/` holds two YAML policies that evaluate the sub-resource directly:

| Policy | Targets | Before fix | After fix |
|---|---|---|---|
| CKV_TMSE_1 | `aws_s3_bucket_acl` `acl` not in `public-read`, `public-read-write`, `authenticated-read` | FAIL on `aws_s3_bucket_acl.seed01_public_acl` | pass |
| CKV_TMSE_2 | `aws_s3_bucket_versioning` `versioning_configuration.status` equals `Enabled` | FAIL on `aws_s3_bucket_versioning.seed03_no_versioning` | pass |

CKV_TMSE_2 also passes on `control01_secure`, so it adds no false positive. With these policies SEED-01 and SEED-03 are detected on their own resources, which closes the 8/10 to 10/10 gap on an exact-resource basis. Note that these policies address a *reporting-location* gap; they are not a response to a missed detection.

### 3.3 False positives and findings on the controls

Checkov raised 6 findings on the two controls, before and after the fix (the controls are identical in both folders). **None is a factual error by Checkov**, so the false-positive count is 0 under the strict definition. Each has a cause:

| Control | Check | Classification | Cause |
|---|---|---|---|
| CONTROL-01 | CKV_AWS_18 (access logging) | best-practice finding | Bucket is locked down but has no logging target. Valid, but outside the seeded categories. |
| CONTROL-01 | CKV_AWS_144 (cross-region replication) | best-practice finding | Resilience feature we deliberately did not configure. |
| CONTROL-01 | CKV_AWS_145 (KMS encryption by default) | best-practice finding | The control uses AES-256 (S3-managed keys), which is encrypted but is not KMS. The check is stricter than "encrypted". |
| CONTROL-01 | CKV2_AWS_61 (lifecycle configuration) | best-practice finding | No lifecycle rules defined. |
| CONTROL-01 | CKV2_AWS_62 (event notifications) | best-practice finding | No notifications configured. |
| CONTROL-02 | CKV2_AWS_5 (security group not attached) | test-fixture artifact | Correct statement: the group is attached to nothing. That is only because the project is scan-only and never deploys instances. |

If the team prefers to count every finding on a control as a false positive, the number is 6. We classify as above because the README distinguishes false positives from best-practice findings.

### 3.4 Where the other 52 findings come from

Of the 67 failed checks on `vulnerable/`, only 15 (22%) were the seeded checks. The rest, by cause (the counts are produced by `score.py` and stored in `results/scorecard.json` under `finding_classes_before`; the corroborating-finding assignments are a judgment call documented in `score.py`):

| Class | Count | Cause |
|---|---|---|
| Expected (seeded) checks | 15 | The detections. |
| Corroborating findings on the same flaw | 10 | Real and correct, from the same root flaw: SEED-05's wildcard also fails CKV2_AWS_40 and CKV_AWS_286 to 290 (6); SEED-09's all-ports rule also fails CKV_AWS_24, CKV_AWS_25, CKV_AWS_260 (3); SEED-02's bucket fails CKV2_AWS_6, which requires the access-block flags to be on (1). Not counted as detections. |
| Independent best-practice findings on seed resources | 30 | Logging, replication, KMS, lifecycle and events on the three S3 seed buckets (15); RDS monitoring, logging, Multi-AZ, IAM auth, minor upgrades, deletion protection, snapshot tags on the two RDS seeds (14); CKV_AWS_273 (use SSO rather than IAM users) on the SEED-06 user (1). Valid and unrelated to the seeded flaws. |
| Controls | 6 | Section 3.3. |
| Supporting-bucket gaps | 4 | The SEED-01 to 03 buckets lack safeguards that other seeds are testing: no public access block (CKV2_AWS_6 on the SEED-01 and SEED-03 buckets) and no versioning resource (CKV_AWS_21 on the SEED-01 and SEED-02 buckets). Correct findings; a side effect of keeping one flaw per seed. |
| Unattached security group | 2 | CKV2_AWS_5 on SEED-08 and SEED-09; same fixture artifact as CONTROL-02. |
| **Total** | **67** | |

### 3.5 Before and after the fix

| | Before (`vulnerable/`) | After (`fixed/`) |
|---|---|---|
| Expected (seeded) check failures | 15 | **0** |
| Seeds still flagged | 10 | **0** |
| All failed checks | 67 | 42 |
| All passed checks | 65 | 90 |
| Resources scanned | 19 | 21 |
| Parsing errors | 0 | 0 |

The drop from 67 to 42 is the 15 seeded failures plus the 10 corroborating findings, which disappear with their root flaw. The remaining 42 are best-practice, supporting-bucket, and fixture findings that we intentionally left alone. The passed counts are not directly comparable because `fixed/` has two more resources (SEED-06's group and membership, replacing one user policy).

## 4. Misses and false positives: each traced to a cause

| Item | Cause |
|---|---|
| SEED-01 reported on parent bucket | CKV_AWS_20 is a graph check on `aws_s3_bucket`; no stock check evaluates the canned ACL on the ACL resource (3.2). |
| SEED-03 reported on parent bucket | CKV_AWS_21 is a graph check on `aws_s3_bucket` (3.2). |
| Genuine misses | None. |
| Genuine false positives | None. |
| 6 control findings | Best-practice checks and one unattached-fixture finding (3.3). |

## 5. Success criteria

| Criterion | Status |
|---|---|
| About 10 misconfigurations across storage, IAM, networking | Met (4 / 3 / 3) |
| Checkov scans locally, no cloud account | Met |
| Detection rate and false positives reported | Met (section 1) |
| Fixes applied; re-scan compared with first scan | Met (3.5) |
| Every miss and false positive traced to a cause | Met (section 4) |
| Custom Checkov policy for a missed misconfiguration | Met in the exact-resource sense only: the "misses" are the 2 attribution cases, not undetected flaws (3.2) |
| Whole cycle reruns with one command | Met (`./run_eval.sh`) |
| Each seed mapped to the check that caught it, or to none | Met (3.1; `results/scorecard.csv`) |

## 6. Limitations

- **Small, self-selected sample.** 10 seeds chosen by us, one scanner at one pinned version, one cloud. The rates describe this sample, not Checkov in general.
- **Seeds were designed around checks Checkov already has.** We picked flaws with a known matching check, so a 100% rate is partly built in. A study that probed for gaps (unusual resources, indirect misconfiguration) would likely find misses that this one could not.
- **Simple, literal configuration.** Every seed is a single resource with literal values. There are no variables, modules, `for_each`, or data sources, which is where static scanners are most likely to lose track of a value.
- **Detection means "an expected check failed", not "the right line was reported".** The linked-detection rule (section 2) widens that definition for two seeds, which is why both rates are shown.
- **Counts depend on the Checkov version.** A different version can add, remove, or renumber checks. The version is pinned for that reason.
- **Terraform was never applied.** Checkov parsed both folders with 0 errors; the configuration was not deployed or planned against AWS.

## Reproduce

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./run_eval.sh              # scan, re-scan, custom policy, score, print summary
./run_eval.sh --write-gt   # same, and fill caught_before / caught_after in ground_truth.csv
```

`caught_before` = an expected check failed on the seed or its family. `caught_after` = an expected check still fails after the fix (the goal is `no`).
