# =============================================================================
# fixed/main.tf
# Terraform Misconfig Scanner Eval: the REMEDIATED config (the "after" half)
# =============================================================================
#
# PURPOSE
#   Same resources and same labels as vulnerable/main.tf, with each seeded flaw
#   corrected. Run `diff vulnerable/main.tf fixed/main.tf` to see exactly what
#   changed. We re-scan this file and check that every expected check from
#   ground_truth.csv stops failing.
#
# RULES FOLLOWED
#   - Only the seeded flaw on each SEED is changed. Everything else is left
#     alone, so unrelated best-practice findings (logging, KMS, replication,
#     and so on) are expected to remain. We are measuring seeded issues, not
#     trying to reach zero findings.
#   - Resource labels match vulnerable/ exactly, with ONE exception: SEED-06
#     has to change resource TYPE (user policy -> group policy) because the
#     flaw is the type of attachment. Its replacement is labelled
#     seed06_group_inline, which still starts with "seed06_" so the scorer
#     counts it as part of the SEED-06 family.
#   - No "checkov:skip" comments. A skip would hide findings, not fix them.
#
# SAFETY
#   - NEVER run `terraform apply` on this file. It is for scanning only.
#
# SYNTAX CHECK (does not touch AWS, does not scan):
#   cd fixed && terraform init -backend=false && terraform validate
# =============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  # Scan-only project: never run terraform apply.
}


# =============================================================================
# CATEGORY: STORAGE
# =============================================================================

# SEED-01 FIX: ACL changed from "public-read" to "private".
resource "aws_s3_bucket" "seed01_public_acl" {
  bucket = "tmse-seed01-public-acl"
}

resource "aws_s3_bucket_acl" "seed01_public_acl" {
  bucket = aws_s3_bucket.seed01_public_acl.id
  acl    = "private" # FIXED: was "public-read"
}


# SEED-02 FIX: all four public-access protections switched on.
resource "aws_s3_bucket" "seed02_no_pab" {
  bucket = "tmse-seed02-no-pab"
}

resource "aws_s3_bucket_public_access_block" "seed02_no_pab" {
  bucket = aws_s3_bucket.seed02_no_pab.id

  block_public_acls       = true # FIXED (CKV_AWS_53)
  block_public_policy     = true # FIXED (CKV_AWS_54)
  ignore_public_acls      = true # FIXED (CKV_AWS_55)
  restrict_public_buckets = true # FIXED (CKV_AWS_56)
}


# SEED-03 FIX: versioning changed from "Suspended" to "Enabled".
resource "aws_s3_bucket" "seed03_no_versioning" {
  bucket = "tmse-seed03-no-versioning"
}

resource "aws_s3_bucket_versioning" "seed03_no_versioning" {
  bucket = aws_s3_bucket.seed03_no_versioning.id

  versioning_configuration {
    status = "Enabled" # FIXED: was "Suspended"
  }
}


# SEED-04 FIX: storage encryption turned on.
resource "aws_db_instance" "seed04_unencrypted_db" {
  identifier        = "tmse-seed04-unencrypted-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username                    = "admin"
  manage_master_user_password = true

  storage_encrypted   = true  # FIXED: was false
  publicly_accessible = false # unchanged (secure)
  skip_final_snapshot = true
}


# =============================================================================
# CATEGORY: IAM
# =============================================================================

# SEED-05 FIX: wildcard replaced with one specific action on one specific
# object path (least privilege).
resource "aws_iam_policy" "seed05_wildcard" {
  name        = "tmse-seed05-wildcard"
  description = "SEED-05 (fixed): read one specific object only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"                                         # FIXED: was "*"
        Resource = "arn:aws:s3:::tmse-seed05-example/reports/summary.txt" # FIXED: was "*" (fake name)
      }
    ]
  })
}


# SEED-06 FIX: the same narrow policy is attached to a GROUP, and the user is
# made a member of that group. Resource type changes from aws_iam_user_policy
# to aws_iam_group_policy, so the label changes too (see header note).
resource "aws_iam_user" "seed06_user" {
  name = "tmse-seed06-user"
}

resource "aws_iam_group" "seed06_group" {
  name = "tmse-seed06-group"
}

resource "aws_iam_user_group_membership" "seed06_membership" {
  user   = aws_iam_user.seed06_user.name
  groups = [aws_iam_group.seed06_group.name]
}

resource "aws_iam_group_policy" "seed06_group_inline" {
  name  = "tmse-seed06-group-inline"
  group = aws_iam_group.seed06_group.name # FIXED: attached to a group, not a user

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::tmse-seed06-example/reports/summary.txt"
      }
    ]
  })
}


# SEED-07 FIX: minimum password length raised from 6 to 14.
resource "aws_iam_account_password_policy" "seed07_weak" {
  minimum_password_length = 14 # FIXED (CKV_AWS_10): was 6

  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  max_password_age             = 90
  password_reuse_prevention    = 24
}


# =============================================================================
# CATEGORY: NETWORKING
# =============================================================================

# SEED-08 FIX: SSH limited to a private internal range (stand-in for a VPN or
# bastion range) instead of 0.0.0.0/0.
resource "aws_security_group" "seed08_ssh_open" {
  name        = "tmse-seed08-ssh-open"
  description = "SEED-08 (fixed): SSH from internal range only"

  ingress {
    description = "SSH from internal range"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # FIXED: was 0.0.0.0/0
  }
}


# SEED-09 FIX: all-ports rule replaced with HTTPS only, from the internal range.
resource "aws_security_group" "seed09_all_ports_open" {
  name        = "tmse-seed09-all-ports-open"
  description = "SEED-09 (fixed): HTTPS from internal range only"

  ingress {
    description = "HTTPS from internal range"
    from_port   = 443             # FIXED: was 0
    to_port     = 443             # FIXED: was 0
    protocol    = "tcp"           # FIXED: was "-1" (all protocols)
    cidr_blocks = ["10.0.0.0/16"] # FIXED: was 0.0.0.0/0
  }
}


# SEED-10 FIX: database no longer publicly accessible.
resource "aws_db_instance" "seed10_public_db" {
  identifier        = "tmse-seed10-public-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username                    = "admin"
  manage_master_user_password = true

  storage_encrypted   = true  # unchanged (secure)
  publicly_accessible = false # FIXED: was true
  skip_final_snapshot = true
}


# =============================================================================
# CONTROLS (unchanged from vulnerable/: they were already safe)
# =============================================================================

resource "aws_s3_bucket" "control01_secure" {
  bucket = "tmse-control01-secure"
}

resource "aws_s3_bucket_public_access_block" "control01_secure" {
  bucket                  = aws_s3_bucket.control01_secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "control01_secure" {
  bucket = aws_s3_bucket.control01_secure.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "control01_secure" {
  bucket = aws_s3_bucket.control01_secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "control02_tight" {
  name        = "tmse-control02-tight"
  description = "CONTROL-02: HTTPS from internal range only"

  ingress {
    description = "HTTPS from internal range"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
