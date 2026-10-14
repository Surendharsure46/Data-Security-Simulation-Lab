# RDS PostgreSQL 17 in private subnets: encrypted, TLS enforced, automated backups, no public access. RDS generates and
# manages the master password in Secrets Manager; the application connection-string secret is derived from it.
variable "name" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "instance_class" { type = string }
variable "allowed_sg_ids" { type = list(string) }
variable "deletion_protection" { type = bool }

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "db" {
  name   = "${var.name}-db"
  vpc_id = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "from_app" {
  count                        = length(var.allowed_sg_ids)
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = var.allowed_sg_ids[count.index]
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_db_parameter_group" "this" {
  name   = var.name
  family = "postgres17"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_db_instance" "this" {
  identifier                      = var.name
  engine                          = "postgres"
  engine_version                  = "17"
  instance_class                  = var.instance_class
  allocated_storage               = 20
  max_allocated_storage           = 200
  storage_type                    = "gp3"
  storage_encrypted               = true
  db_name                         = "threatready"
  username                        = "threatready_owner"
  manage_master_user_password     = true
  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  parameter_group_name            = aws_db_parameter_group.this.name
  publicly_accessible             = false
  backup_retention_period         = 14
  copy_tags_to_snapshot           = true
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = !var.deletion_protection
  final_snapshot_identifier       = var.deletion_protection ? "${var.name}-final" : null
  auto_minor_version_upgrade      = true
  performance_insights_enabled    = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

data "aws_secretsmanager_secret_version" "master" {
  secret_id = aws_db_instance.this.master_user_secret[0].secret_arn
}

# THREATREADY_DATABASE_URL for the tasks. After an RDS master-password rotation, re-apply to refresh this value.
resource "aws_secretsmanager_secret" "url" {
  name = "${var.name}/database-url"
}

resource "aws_secretsmanager_secret_version" "url" {
  secret_id = aws_secretsmanager_secret.url.id
  secret_string = format("postgres://%s:%s@%s/%s?sslmode=require",
    aws_db_instance.this.username,
    urlencode(jsondecode(data.aws_secretsmanager_secret_version.master.secret_string)["password"]),
    aws_db_instance.this.endpoint,
    aws_db_instance.this.db_name)
}

output "url_secret_arn" { value = aws_secretsmanager_secret.url.arn }
output "security_group_id" { value = aws_security_group.db.id }
