provider "aws" {
  region = var.region

  # Every resource created by Terraform gets these tags
  default_tags {
    tags = {
      Project   = "cloud-security-checker"
      ManagedBy = "terraform"
    }
  }
}

# Used to build ARNs without writing the account ID in the code
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}