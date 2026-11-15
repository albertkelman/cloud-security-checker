terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # State is stored in a private, versioned S3 bucket (created by hand, see NOTES.md)
  backend "s3" {
    bucket       = "csc-tfstate-qxkgnltd"
    key          = "cloud-security-checker/terraform.tfstate"
    region       = "ap-southeast-2"
    encrypt      = true
    use_lockfile = true
  }
}