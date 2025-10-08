# Test bucket for CI/CD policy validation (intentionally risky for Checkov scanning)
resource "aws_s3_bucket" "bad_public" {
  bucket        = "dg-demo-bad-bucket-example-please-change" # must be globally unique
  force_destroy = true
  
  tags = {
    env     = "sandbox"
    project = "driftguard"
  }
}

# Disable Public Access Block to allow the test policy (intentionally risky)
resource "aws_s3_bucket_public_access_block" "bad_public" {
  bucket = aws_s3_bucket.bad_public.id
  
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Intentionally risky bucket policy for testing Checkov policies
resource "aws_s3_bucket_policy" "bad_public" {
  bucket = aws_s3_bucket.bad_public.id
  
  # Ensure Public Access Block is disabled before applying policy
  depends_on = [aws_s3_bucket_public_access_block.bad_public]
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.bad_public.arn}/*"
      }
    ]
  })
}