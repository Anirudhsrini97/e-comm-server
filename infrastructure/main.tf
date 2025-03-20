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

# 1️⃣ Create an AWS KMS RSA 2048 Key
resource "aws_kms_key" "app_kms_key" {
  description             = "KMS RSA 2048 key for password encryption"
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "RSA_2048"
  is_enabled              = true
  enable_key_rotation     = true
}

resource "aws_kms_alias" "app_kms_key_alias" {
  name          = "alias/my-app-kms-key"
  target_key_id = aws_kms_key.app_kms_key.id
}

# 2️⃣ Store Secrets in AWS Secrets Manager with KMS Encryption
resource "aws_secretsmanager_secret" "app_secrets" {
  name        = "my-app-secrets"
  description = "Secrets for Flask app"
  #kms_key_id  = aws_kms_key.app_kms_key.arn # Use KMS Key for encryption
}

resource "aws_secretsmanager_secret_version" "secrets_values" {
  secret_id     = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    jwt_secret_key = var.jwt_secret_key
    db_user        = var.db_user
    db_password    = var.db_password
    db_host        = var.db_host
    db_port        = var.db_port
    db_name        = var.db_name
    kms_key_id     = aws_kms_key.app_kms_key.arn
  })
}
