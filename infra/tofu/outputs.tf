# Values for the GitHub repository variables used by .github/workflows/deploy.yml.
output "AWS_REGION" { value = var.aws_region }
output "AWS_DEPLOY_ROLE_ARN" { value = module.github_oidc.role_arn }
output "ECR_REPOSITORY" { value = module.app.ecr_repository_name }
output "ECS_CLUSTER" { value = module.app.cluster_name }
output "ECS_NETWORK_CONFIGURATION" { value = module.app.network_configuration }
output "app_url" { value = "https://${var.domain}" }
