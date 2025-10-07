terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
provider "aws" {
  region = "us-west-2"
  skip_credentials_validation  = true
  skip_requesting_account_id   = true
  skip_region_validation       = true
}
resource "aws_security_group" "bad_ssh" {
  name = "bad-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # intentionally bad for test
  }
}
