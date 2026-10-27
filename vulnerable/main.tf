# =============================================================================
# vulnerable/main.tf
# Terraform Misconfig Scanner Eval: the SEEDED (intentionally insecure) config
# =============================================================================
#
# STATUS
#   Seeds 01-10 and both controls are written. No TODO blocks remain.
#
# PURPOSE
#   This file is the "before" half of the experiment. It contains 10 planted
#   misconfigurations (seeds) plus 2 deliberately safe resources (controls).
#   We scan it with Checkov and compare the findings to ground_truth.csv.
#
# CONVENTIONS
#   - SEED-NN    = a planted flaw. Each one is listed in ground_truth.csv.
#   - CONTROL-NN = a correctly configured resource. Anything Checkov flags on
#                  a control has to be classified as a false positive or a
#                  best-practice finding.
#   - Resource labels (the second word after "resource") MUST match the
#     "resource" column in ground_truth.csv exactly. If you rename one here,
#     rename it in the CSV in the same commit.
#   - ONE FLAW PER SEED. Every other setting on a seed resource is kept
#     secure, so only the seeded flaw should fail the expected check(s).
#     Checkov may still report unrelated best-practice findings (logging,
#     backups, KMS keys, and so on). Those are expected. They are recorded as
#     "unrelated findings" and never counted as detections.
#   - SUPPORTING resources (a bucket for an ACL to attach to, a user for a
#     policy to attach to) are marked as such. They exist only so the seed
#     resource is valid Terraform. They are not seeds and are not scored.
#   - Names start with "tmse-" (terraform-misconfig-scanner-eval) and are fake.
#
# SAFETY
#   - NEVER run `terraform apply` on this file. It is for scanning only.
#   - No real credentials or secrets belong in this file. Use obvious fakes.
#   - Do not add "checkov:skip" comments. They would hide the findings we
#     are trying to measure.
#
# SYNTAX CHECK (does not touch AWS, does not scan):
#   cd vulnerable && terraform init -backend=false && terraform validate
# =============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # pinned to 5.x so resource arguments stay consistent
    }
  }
}

# The provider block tells Terraform which cloud and region this config targets.
# Checkov reads the files as text and never contacts AWS, so no credentials are
# needed anywhere in this project.
provider "aws" {
  region = "us-east-1"
}


# =============================================================================
# CATEGORY: STORAGE
# =============================================================================

# -----------------------------------------------------------------------------
# SEED-01 | storage | S3 bucket ACL grants public read
# Expected Checkov check: CKV_AWS_20
#
# What is wrong:   An ACL (access control list) of "public-read" lets anyone on
#                  the internet list the bucket's contents without logging in.
# Why it matters:  This is the classic "exposed bucket" breach pattern: customer
#                  data, backups, or credentials sitting in a world-readable
#                  bucket that nobody noticed.
# -----------------------------------------------------------------------------

# SUPPORTING resource (not scored): the bucket the ACL is attached to.
resource "aws_s3_bucket" "seed01_public_acl" {
  bucket = "tmse-seed01-public-acl" # fake name; S3 names are globally unique
}

# THE SEED: the ACL resource itself.
resource "aws_s3_bucket_acl" "seed01_public_acl" {
  bucket = aws_s3_bucket.seed01_public_acl.id # links this ACL to the bucket above
  acl    = "public-read"                      # <-- FLAW: readable by everyone
}


# -----------------------------------------------------------------------------
# SEED-02 | storage | S3 public access block fully disabled
# Expected Checkov checks: CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56
#
# What is wrong:   The "public access block" is a safety net that overrides bad
#                  ACLs and bucket policies. Here all four protections are off.
#                  Each one maps to one Checkov check (53 to 56).
# Why it matters:  With the net removed, one mistake in an ACL or policy is
#                  enough to expose the bucket. This is defense in depth lost.
# Scoring note:    Any ONE of the four expected checks failing counts as a
#                  detection. In the report, note how many of the four fired.
# -----------------------------------------------------------------------------

# SUPPORTING resource (not scored)
resource "aws_s3_bucket" "seed02_no_pab" {
  bucket = "tmse-seed02-no-pab"
}

# THE SEED
resource "aws_s3_bucket_public_access_block" "seed02_no_pab" {
  bucket = aws_s3_bucket.seed02_no_pab.id

  block_public_acls       = false # <-- FLAW (CKV_AWS_53): public ACLs allowed
  block_public_policy     = false # <-- FLAW (CKV_AWS_54): public bucket policies allowed
  ignore_public_acls      = false # <-- FLAW (CKV_AWS_55): existing public ACLs are honored
  restrict_public_buckets = false # <-- FLAW (CKV_AWS_56): public policies stay effective
}


# -----------------------------------------------------------------------------
# SEED-03 | storage | S3 versioning suspended
# Expected Checkov check: CKV_AWS_21
#
# What is wrong:   Versioning keeps old copies of every object. "Suspended"
#                  means overwrites and deletes are permanent.
# Why it matters:  Accidental deletion or a ransomware-style overwrite cannot be
#                  rolled back. This is an integrity and recovery weakness
#                  rather than an exposure, which makes it a good contrast to
#                  SEED-01 and SEED-02.
# -----------------------------------------------------------------------------

# SUPPORTING resource (not scored)
resource "aws_s3_bucket" "seed03_no_versioning" {
  bucket = "tmse-seed03-no-versioning"
}

# THE SEED
resource "aws_s3_bucket_versioning" "seed03_no_versioning" {
  bucket = aws_s3_bucket.seed03_no_versioning.id

  versioning_configuration {
    status = "Suspended" # <-- FLAW: "Enabled" is the secure value
  }
}


# -----------------------------------------------------------------------------
# SEED-04 | storage | RDS database storage not encrypted
# Expected Checkov check: CKV_AWS_16
#
# What is wrong:   storage_encrypted = false means the database disk, its
#                  snapshots, and its backups are stored unencrypted.
# Why it matters:  Encryption at rest protects data if a snapshot is shared by
#                  mistake or underlying storage is accessed. Many compliance
#                  frameworks (PCI DSS, HIPAA) require it. Encryption cannot be
#                  switched on later for an existing instance without
#                  recreating it from an encrypted snapshot, so getting it
#                  wrong at creation is costly.
# One-flaw rule:   publicly_accessible is set to false below so this resource
#                  does not also trigger CKV_AWS_17 (that belongs to SEED-10).
# -----------------------------------------------------------------------------
resource "aws_db_instance" "seed04_unencrypted_db" {
  identifier        = "tmse-seed04-unencrypted-db" # name of the DB in AWS
  engine            = "mysql"                      # database software
  instance_class    = "db.t3.micro"                # smallest, cheapest size (never deployed anyway)
  allocated_storage = 20                           # disk size in GB

  username                    = "admin" # master username (not a secret)
  manage_master_user_password = true    # AWS generates the password and stores it in Secrets Manager.
                                        # This avoids a hardcoded password so Checkov's secret
                                        # detection does not add unrelated noise.

  storage_encrypted   = false # <-- FLAW: should be true
  publicly_accessible = false # kept SECURE here on purpose (SEED-10 breaks this one)
  skip_final_snapshot = true  # lets the resource be destroyed without a snapshot; irrelevant to the flaw
}


# =============================================================================
# CATEGORY: IAM (identity and access management)
# =============================================================================

# -----------------------------------------------------------------------------
# SEED-05 | iam | Policy allows every action on every resource
# Expected Checkov checks: CKV_AWS_62, CKV_AWS_63, CKV_AWS_355
#
# What is wrong:   Action "*" plus Resource "*" is full administrator access.
#                    CKV_AWS_62  = full "*-*" admin privileges
#                    CKV_AWS_63  = wildcard in Action
#                    CKV_AWS_355 = wildcard in Resource
# Why it matters:  Violates least privilege. Whoever holds this policy (or an
#                  attacker who steals their credentials) can do anything in
#                  the account. Wildcard IAM is one of the most common
#                  misconfigurations behind real cloud breaches.
# Scoring note:    Any ONE of the three expected checks failing counts as a
#                  detection. In the report, note how many of the three fired.
# -----------------------------------------------------------------------------
resource "aws_iam_policy" "seed05_wildcard" {
  name        = "tmse-seed05-wildcard"
  description = "SEED-05: allows all actions on all resources"

  # jsonencode() turns this Terraform map into the JSON that AWS expects for
  # IAM policy documents.
  policy = jsonencode({
    Version = "2012-10-17" # IAM policy language version; this exact string is standard
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*" # <-- FLAW: every AWS API action
        Resource = "*" # <-- FLAW: every resource in the account
      }
    ]
  })
}


# -----------------------------------------------------------------------------
# SEED-06 | iam | Policy attached directly to a user
# Expected Checkov check: CKV_AWS_40
#
# What is wrong:   The permissions are attached straight to an individual IAM
#                  user instead of to a group or a role. The flaw is HOW the
#                  policy is attached, not what the policy says.
# Why it matters:  Per-user policies are hard to audit and easy to forget.
#                  When someone changes teams or leaves, their direct
#                  permissions have to be hunted down one user at a time,
#                  which leads to permission sprawl and orphaned access. Groups
#                  and roles give one place to review and revoke access.
# One-flaw rule:   The policy content is deliberately NARROW: one specific
#                  action on one specific object path, no "*" wildcards. That
#                  keeps it from tripping SEED-05's checks (CKV_AWS_62,
#                  CKV_AWS_63, CKV_AWS_355) and blurring the results.
# -----------------------------------------------------------------------------

# SUPPORTING resource (not scored): the user the policy is attached to.
resource "aws_iam_user" "seed06_user" {
  name = "tmse-seed06-user" # fake user; no access keys or login profile are created
}

# THE SEED
resource "aws_iam_user_policy" "seed06_user_inline" {
  name = "tmse-seed06-user-inline"
  user = aws_iam_user.seed06_user.name # <-- FLAW: attached to a user, not a group or role

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"                                         # one specific action
        Resource = "arn:aws:s3:::tmse-seed06-example/reports/summary.txt" # one specific object, fake name
      }
    ]
  })
}


# -----------------------------------------------------------------------------
# SEED-07 | iam | Weak account password policy (minimum length 6)
# Expected Checkov check: CKV_AWS_10
#
# What is wrong:   The account password policy accepts passwords as short as 6
#                  characters. The check wants a minimum length of 14 or more.
# Why it matters:  Short passwords fall quickly to brute-force and credential
#                  stuffing attacks. Benchmarks such as CIS AWS Foundations
#                  call for a long minimum length for IAM console users.
# One-flaw rule:   Every OTHER requirement is set to a secure value (lowercase,
#                  uppercase, numbers, symbols, 90-day max age, reuse
#                  prevention of 24) so only the length check fails.
# -----------------------------------------------------------------------------
resource "aws_iam_account_password_policy" "seed07_weak" {
  minimum_password_length = 6 # <-- FLAW (CKV_AWS_10): should be 14 or more

  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  max_password_age             = 90 # days until a password must be changed
  password_reuse_prevention    = 24 # remember the last 24 passwords
}


# =============================================================================
# CATEGORY: NETWORKING
# =============================================================================

# -----------------------------------------------------------------------------
# SEED-08 | networking | SSH open to the whole internet
# Expected Checkov check: CKV_AWS_24
#
# What is wrong:   One ingress rule allows TCP port 22 (SSH) from 0.0.0.0/0,
#                  which means every IP address on the internet.
# Why it matters:  Exposed SSH is probed by automated scanners within minutes
#                  of going live. It invites brute-force logins and attacks on
#                  any unpatched SSH daemon. Admin access should be limited to
#                  a known range, a VPN, or a managed alternative such as
#                  Session Manager.
# One-flaw rule:   The rule has a description so CKV_AWS_23 (rule descriptions)
#                  stays quiet. Checkov may still report unrelated findings,
#                  such as the group not being attached to any resource.
# -----------------------------------------------------------------------------
resource "aws_security_group" "seed08_ssh_open" {
  name        = "tmse-seed08-ssh-open"
  description = "SEED-08: SSH open to the internet"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # <-- FLAW: the whole internet
  }
}


# -----------------------------------------------------------------------------
# SEED-09 | networking | ALL ports open to the whole internet
# Expected Checkov check: CKV_AWS_277
#
# What is wrong:   One ingress rule uses protocol "-1" (all protocols) with
#                  ports 0 to 0, which AWS treats as every port, from
#                  0.0.0.0/0 (every IP address on the internet).
# Why it matters:  Every service listening on the instance is reachable by
#                  anyone, including databases, admin panels, and debug
#                  ports that were never meant to be public. It is the
#                  networking equivalent of removing the firewall.
# Scoring note:    Other security-group checks may also fire on this resource
#                  (for example CKV_AWS_24, since "all ports" includes 22).
#                  Those are unrelated findings. Only CKV_AWS_277 counts as
#                  the detection.
# -----------------------------------------------------------------------------
resource "aws_security_group" "seed09_all_ports_open" {
  name        = "tmse-seed09-all-ports-open"
  description = "SEED-09: all ports open to the internet"

  ingress {
    description = "All traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"          # <-- FLAW: all protocols and all ports
    cidr_blocks = ["0.0.0.0/0"] # <-- FLAW: the whole internet
  }
}


# -----------------------------------------------------------------------------
# SEED-10 | networking | RDS database publicly accessible
# Expected Checkov check: CKV_AWS_17
#
# What is wrong:   publicly_accessible = true gives the database a public IP
#                  address and a DNS name that resolves to it, so it can be
#                  reached from the internet (subject to security groups).
# Why it matters:  Databases should sit on private networks and be reached
#                  through an application tier or a bastion. A public endpoint
#                  makes the database a direct target for credential guessing
#                  and for exploits against the database engine.
# One-flaw rule:   storage_encrypted is set to true so CKV_AWS_16 does not fire
#                  on this resource (that check belongs to SEED-04).
# -----------------------------------------------------------------------------
resource "aws_db_instance" "seed10_public_db" {
  identifier        = "tmse-seed10-public-db" # name of the DB in AWS
  engine            = "mysql"                 # database software
  instance_class    = "db.t3.micro"           # smallest, cheapest size (never deployed anyway)
  allocated_storage = 20                      # disk size in GB

  username                    = "admin" # master username (not a secret)
  manage_master_user_password = true    # AWS generates the password and stores it in Secrets Manager.
                                        # This avoids a hardcoded password so Checkov's secret
                                        # detection does not add unrelated noise.

  storage_encrypted   = true # kept SECURE here on purpose (SEED-04 breaks this one)
  publicly_accessible = true # <-- FLAW: should be false
  skip_final_snapshot = true # lets the resource be destroyed without a snapshot; irrelevant to the flaw
}


# =============================================================================
# CONTROLS (deliberately SAFE; used to measure false positives)
# =============================================================================
# A control is a resource we believe is correctly configured for the category
# it represents. If Checkov fails a check on a control, we investigate each
# finding by hand and classify it in report.md:
#   - FALSE POSITIVE:       the check is wrong about what the config does.
#   - BEST-PRACTICE FINDING: the config is secure for the seeded category, but a
#                            stricter or unrelated check (logging, KMS key,
#                            and so on) still fires.
# Expect some control findings. They are data, not mistakes.
# =============================================================================

# -----------------------------------------------------------------------------
# CONTROL-01 | storage | properly locked-down S3 bucket
# Mirrors the storage seeds: public access fully blocked, versioning on,
# encryption on.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "control01_secure" {
  bucket = "tmse-control01-secure"
}

# All four protections ON (contrast with SEED-02, where all four are off).
resource "aws_s3_bucket_public_access_block" "control01_secure" {
  bucket                  = aws_s3_bucket.control01_secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning ENABLED (contrast with SEED-03, where it is suspended).
resource "aws_s3_bucket_versioning" "control01_secure" {
  bucket = aws_s3_bucket.control01_secure.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption at rest using S3-managed keys (AES-256).
resource "aws_s3_bucket_server_side_encryption_configuration" "control01_secure" {
  bucket = aws_s3_bucket.control01_secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------------------------------
# CONTROL-02 | networking | tight security group
# Mirrors the networking seeds: HTTPS only, and only from a private internal
# range (not the internet).
# -----------------------------------------------------------------------------
resource "aws_security_group" "control02_tight" {
  name        = "tmse-control02-tight"
  description = "CONTROL-02: HTTPS from internal range only"

  ingress {
    description = "HTTPS from internal range"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # private address range, NOT 0.0.0.0/0
  }
}