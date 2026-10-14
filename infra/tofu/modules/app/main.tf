# One container image, three task definitions on ECS Fargate (ARM64 / Graviton):
#   threatready-api      HTTP API + static web app behind the ALB (THREATREADY_ROLE=api)
#   threatready-worker   background jobs, no ingress            (THREATREADY_ROLE=worker)
#   threatready-migrate  one-off migration task run by the deploy workflow before services roll
# Lab artefacts (per-user encrypted files and SQLite lab databases) live on EFS so every api task sees the same files.

variable "name" { type = string }
variable "environment" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "private_subnet_ids" { type = list(string) }
variable "domain" { type = string }
variable "api_desired_count" { type = number }
variable "database_url_secret_arn" { type = string }
variable "storage_bucket_arn" { type = string }
variable "storage_bucket_name" {
  type        = string
  description = "Reserved for the S3 StoragePort adapter (not implemented in this release)."
}
variable "certificate_arn" { type = string }
variable "allowed_ingress_cidrs" { type = list(string) }
variable "sentry_dsn" {
  type      = string
  sensitive = true
}

locals {
  port = 8000
  common_env = [
    { name = "THREATREADY_ENV", value = var.environment == "production" ? "production" : "development" },
    { name = "THREATREADY_PUBLIC_URL", value = "https://${var.domain}" },
    { name = "THREATREADY_TRUSTED_ORIGINS", value = "https://${var.domain}" },
    { name = "THREATREADY_LAB_DATA_DIR", value = "/data/labs" },
    { name = "THREATREADY_STORAGE_DRIVER", value = "local" },
    { name = "THREATREADY_MAIL_DRIVER", value = "console" },
    { name = "THREATREADY_SENTRY_DSN", value = var.sentry_dsn },
  ]
  common_secrets = [
    { name = "THREATREADY_DATABASE_URL", valueFrom = var.database_url_secret_arn },
    { name = "THREATREADY_AUTH_SECRET", valueFrom = aws_secretsmanager_secret.auth.arn },
  ]
}

# --------------------------------------------------------------------------- registry, logs, secrets

resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "KMS" }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy = jsonencode({ rules = [{ rulePriority = 1, description = "Keep the last 30 images",
    selection = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 30 }, action = { type = "expire" } }] })
}

resource "aws_cloudwatch_log_group" "this" {
  for_each          = toset(["api", "worker", "migrate"])
  name              = "/ecs/${var.name}-${each.key}"
  retention_in_days = 90
}

resource "random_password" "auth" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "auth" {
  name = "${var.name}-${var.environment}/auth-secret"
}

resource "aws_secretsmanager_secret_version" "auth" {
  secret_id     = aws_secretsmanager_secret.auth.id
  secret_string = random_password.auth.result
}

# --------------------------------------------------------------------------- IAM

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-${var.environment}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  role = aws_iam_role.execution.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"],
    Resource = [var.database_url_secret_arn, aws_secretsmanager_secret.auth.arn] }] })
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-${var.environment}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "task" {
  role = aws_iam_role.task.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${var.storage_bucket_arn}/*" },
    { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.storage_bucket_arn },
    { Effect = "Allow", Action = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"], Resource = aws_efs_file_system.labs.arn },
  ] })
}

# --------------------------------------------------------------------------- network security

resource "aws_security_group" "alb" {
  name   = "${var.name}-${var.environment}-alb"
  vpc_id = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count             = length(var.allowed_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = var.allowed_ingress_cidrs[count.index]
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = local.port
  to_port                      = local.port
}

resource "aws_security_group" "task" {
  name   = "${var.name}-${var.environment}-task"
  vpc_id = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "task_from_alb" {
  security_group_id            = aws_security_group.task.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = local.port
  to_port                      = local.port
}

resource "aws_vpc_security_group_egress_rule" "task_all" {
  security_group_id = aws_security_group.task.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # ECR, Secrets Manager, Sentry, RDS, EFS
}

resource "aws_security_group" "efs" {
  name   = "${var.name}-${var.environment}-efs"
  vpc_id = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_tasks" {
  security_group_id            = aws_security_group.efs.id
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
}

# --------------------------------------------------------------------------- lab file system

resource "aws_efs_file_system" "labs" {
  encrypted        = true
  performance_mode = "generalPurpose"
  throughput_mode  = "elastic"
  tags             = { Name = "${var.name}-${var.environment}-labs" }
}

resource "aws_efs_mount_target" "labs" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.labs.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "labs" {
  file_system_id = aws_efs_file_system.labs.id
  posix_user {
    uid = 1000 # the image's "node" user
    gid = 1000
  }
  root_directory {
    path = "/labs"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "0750"
    }
  }
}

# --------------------------------------------------------------------------- load balancer

resource "aws_lb" "this" {
  name                       = "${var.name}-${var.environment}"
  load_balancer_type         = "application"
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.environment == "production"
}

resource "aws_lb_target_group" "api" {
  name        = "${var.name}-${var.environment}-api"
  port        = local.port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    path                = "/api/health"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
  }
  deregistration_delay = 30
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# --------------------------------------------------------------------------- ECS

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-${var.environment}"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  image = "${aws_ecr_repository.this.repository_url}:bootstrap" # replaced by the deploy workflow on every release
  volume_mount = [{ sourceVolume = "labs", containerPath = "/data/labs", readOnly = false }]
}

resource "aws_ecs_task_definition" "this" {
  for_each = {
    api     = { role = "api", cpu = 512, memory = 1024, command = null }
    worker  = { role = "worker", cpu = 256, memory = 512, command = null }
    migrate = { role = "worker", cpu = 256, memory = 512, command = ["node", "dist/cli.js", "migrate"] }
  }
  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  volume {
    name = "labs"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.labs.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.labs.id
        iam             = "ENABLED"
      }
    }
  }
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = local.image
    essential              = true
    command                = each.value.command
    readonlyRootFilesystem = false
    user                   = "1000:1000"
    portMappings           = each.key == "api" ? [{ containerPort = local.port, protocol = "tcp" }] : []
    environment            = concat(local.common_env, [{ name = "THREATREADY_ROLE", value = each.value.role }])
    secrets                = local.common_secrets
    mountPoints            = local.volume_mount
    logConfiguration = {
      logDriver = "awslogs"
      options = { "awslogs-group" = aws_cloudwatch_log_group.this[each.key].name, "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = each.key }
    }
  }])
  lifecycle { ignore_changes = [container_definitions] } # the deploy workflow owns the image tag
}

resource "aws_ecs_service" "api" {
  name                              = "${var.name}-api"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.this["api"].arn
  desired_count                     = var.api_desired_count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true # egress without a NAT gateway; ingress is restricted to the ALB security group
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = local.port
  }
  depends_on = [aws_lb_listener.https, aws_efs_mount_target.labs]
  lifecycle { ignore_changes = [task_definition] }
}

resource "aws_ecs_service" "worker" {
  name            = "${var.name}-worker"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this["worker"].arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true
  }
  depends_on = [aws_efs_mount_target.labs]
  lifecycle { ignore_changes = [task_definition] }
}

output "ecr_repository_arn" { value = aws_ecr_repository.this.arn }
output "ecr_repository_name" { value = aws_ecr_repository.this.name }
output "cluster_arn" { value = aws_ecs_cluster.this.arn }
output "cluster_name" { value = aws_ecs_cluster.this.name }
output "alb_dns_name" { value = aws_lb.this.dns_name }
output "task_security_group_id" { value = aws_security_group.task.id }
output "task_role_arns" { value = [aws_iam_role.execution.arn, aws_iam_role.task.arn] }
output "network_configuration" {
  value = "awsvpcConfiguration={subnets=[${join(",", var.public_subnet_ids)}],securityGroups=[${aws_security_group.task.id}],assignPublicIp=ENABLED}"
}
