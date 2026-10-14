# Cloudflare in front of the ALB: proxied DNS record (TLS, WAF, DDoS), strict TLS to the origin, plus the ACM certificate
# for the ALB validated through Cloudflare DNS. The ALB only accepts traffic from Cloudflare's published IP ranges.
terraform {
  required_providers {
    aws        = { source = "hashicorp/aws" }
    cloudflare = { source = "cloudflare/cloudflare" }
  }
}

variable "zone_id" { type = string }
variable "domain" { type = string }
variable "alb_dns_name" { type = string }

data "cloudflare_ip_ranges" "this" {}

resource "aws_acm_certificate" "origin" {
  domain_name       = var.domain
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}

resource "cloudflare_dns_record" "validation" {
  for_each = { for o in aws_acm_certificate.origin.domain_validation_options : o.domain_name => o }
  zone_id  = var.zone_id
  name     = trimsuffix(each.value.resource_record_name, ".")
  type     = each.value.resource_record_type
  content  = trimsuffix(each.value.resource_record_value, ".")
  ttl      = 60
  proxied  = false
}

resource "aws_acm_certificate_validation" "origin" {
  certificate_arn         = aws_acm_certificate.origin.arn
  validation_record_fqdns = [for r in cloudflare_dns_record.validation : r.name]
}

resource "cloudflare_dns_record" "app" {
  zone_id = var.zone_id
  name    = var.domain
  type    = "CNAME"
  content = var.alb_dns_name
  ttl     = 1 # automatic (proxied)
  proxied = true
}

resource "cloudflare_zone_setting" "ssl" {
  zone_id    = var.zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "always_https" {
  zone_id    = var.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

output "certificate_arn" { value = aws_acm_certificate_validation.origin.certificate_arn }
output "origin_ingress_cidrs" { value = data.cloudflare_ip_ranges.this.ipv4_cidrs }
