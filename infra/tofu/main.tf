# Threatready on AWS: VPC (public + private subnets, no NAT for the database), RDS PostgreSQL, S3 for artefacts, ECS Fargate
# (ARM64) running one image as two services (api behind an ALB, worker without ingress), Cloudflare DNS + proxy in front.
# Secrets live in Secrets Manager / SSM and are injected into the tasks; nothing secret is in state outputs or images.

module "network" {
  source      = "./modules/network"
  name        = "threatready-${var.environment}"
  cidr_block  = "10.40.0.0/16"
  az_count    = 2
}

module "database" {
  source             = "./modules/database"
  name               = "threatready-${var.environment}"
  vpc_id             = module.network.vpc_id
  subnet_ids         = module.network.private_subnet_ids
  instance_class     = var.db_instance_class
  allowed_sg_ids     = [module.app.task_security_group_id]
  deletion_protection = var.environment == "production"
}

module "storage" {
  source = "./modules/storage"
  name   = "threatready-${var.environment}"
}

module "app" {
  source                 = "./modules/app"
  name                   = "threatready"
  environment            = var.environment
  aws_region             = var.aws_region
  vpc_id                 = module.network.vpc_id
  public_subnet_ids      = module.network.public_subnet_ids
  private_subnet_ids     = module.network.private_subnet_ids
  domain                 = var.domain
  api_desired_count      = var.api_desired_count
  database_url_secret_arn = module.database.url_secret_arn
  storage_bucket_arn     = module.storage.bucket_arn
  storage_bucket_name    = module.storage.bucket_name
  certificate_arn        = module.edge.certificate_arn
  allowed_ingress_cidrs  = module.edge.origin_ingress_cidrs
  sentry_dsn             = var.sentry_dsn
}

module "edge" {
  source       = "./modules/edge"
  zone_id      = var.cloudflare_zone_id
  domain       = var.domain
  alb_dns_name = module.app.alb_dns_name
}

module "github_oidc" {
  source            = "./modules/github_oidc"
  github_repository = var.github_repository
  ecr_repository_arn = module.app.ecr_repository_arn
  ecs_cluster_arn   = module.app.cluster_arn
  task_role_arns    = module.app.task_role_arns
}
