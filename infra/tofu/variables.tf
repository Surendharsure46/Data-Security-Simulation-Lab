variable "aws_region" {
  type    = string
  default = "eu-west-2"
}
variable "environment" {
  type    = string
  default = "production"
}
variable "domain" {
  type        = string
  description = "Public hostname of the app, e.g. app.threatready.example (DNS zone hosted in Cloudflare)."
}
variable "cloudflare_zone_id" {
  type = string
}
variable "github_repository" {
  type        = string
  description = "owner/repo allowed to deploy through GitHub OIDC."
}
variable "api_desired_count" {
  type    = number
  default = 2
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}
variable "sentry_dsn" {
  type      = string
  default   = ""
  sensitive = true
}
