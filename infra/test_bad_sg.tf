# ❌ intentionally risky for CI test only
resource "aws_security_group" "bad_ssh" {
  name = "bad-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
