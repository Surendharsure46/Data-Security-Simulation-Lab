terraform {
  required_version = ">= 1.8.0" # OpenTofu
  required_providers {
    aws        = { source = "hashicorp/aws", version = "~> 6.0" }
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 5.0" }
    random     = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # State in S3 with native locking. Create the bucket once, then: tofu init -backend-config=backend.hcl
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
  default_tags { tags = { project = "threatready", environment = var.environment, managed_by = "opentofu" } }
}

provider "cloudflare" {} # CLOUDFLARE_API_TOKEN from the environment
