# DriftGuard Infrastructure

## AWS Credentials Setup
Before running any commands, verify your AWS credentials:

```bash
aws-vault exec driftguard --duration=1h -- aws sts get-caller-identity
```

Then run all `terraform` and test commands **inside** the same `aws-vault` session.

## Manual Testing (Step 4)
We're using manual drift simulation instead of Terraform test resources. Test resources are disabled (renamed to `*.tf.disabled`).

## Quick Commands
- `make lambda-package` - Build Lambda deployment package
- `make apply-core` - Deploy core infrastructure
- `make destroy-core` - Destroy all infrastructure
