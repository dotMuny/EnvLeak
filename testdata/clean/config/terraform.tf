variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_db_instance" "main" {
  identifier = "app-prod"
  username   = "app"
  password   = var.db_password
}

provider "aws" {
  region = "eu-west-1"
  # credentials come from the instance profile
}
