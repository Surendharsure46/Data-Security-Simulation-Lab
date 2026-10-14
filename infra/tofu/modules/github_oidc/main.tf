# GitHub Actions deploys through OIDC: no long-lived AWS keys. The role is limited to the main branch of one repository
# and to pushing this ECR repository, registering task definitions, running the migrate task and updating the services.
variable "github_repository" { type = string }
variable "ecr_repository_arn" { type = string }
variable "ecs_cluster_arn" { type = string }
variable "task_role_arns" { type = list(string) }

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:production"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "threatready-github-deploy"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "deploy" {
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Resource = var.ecr_repository_arn, Action = [
        "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
        "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"] },
      { Effect = "Allow", Action = ["ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition"], Resource = "*" },
      { Effect = "Allow", Action = ["ecs:RunTask", "ecs:DescribeTasks", "ecs:UpdateService", "ecs:DescribeServices"], Resource = "*",
        Condition = { ArnEquals = { "ecs:cluster" = var.ecs_cluster_arn } } },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = var.task_role_arns },
    ]
  })
}

output "role_arn" { value = aws_iam_role.deploy.arn }
