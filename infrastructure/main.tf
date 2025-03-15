provider "aws" {
  region = "us-east-1"
}

terraform {
  backend "s3" {
    bucket = "my-demo-server-bucket"
    key    = "secrets-manager/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_secretsmanager_secret" "app_secrets" {
  name        = "my-app-secrets"
  description = "Secrets for Flask app"
}

resource "aws_secretsmanager_secret_version" "secrets_values" {
  secret_id     = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    jwt_secret_key = var.jwt_secret_key
    db_user        = var.db_user
    db_password    = var.db_password
    db_host        = var.db_host
    db_port        = var.db_port
  })
}
