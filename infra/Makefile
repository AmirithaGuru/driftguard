.PHONY: lambda-package plan-json policy-check tf-apply apply-core destroy-core

# Build Lambda deployment package
lambda-package:
	cd lambda && zip -r remediator.zip remediator.py && mv remediator.zip ..

# Generate Terraform plan JSON for policy validation
plan-json:
	terraform plan -out=plan.bin
	terraform show -json plan.bin > plan.json
	@echo "Plan JSON generated at plan.json"

# Run policy validation with Conftest
policy-check:
	@if [ -f plan.json ]; then \
		conftest test plan.json -p ../policy --data ../policy/exceptions.yaml; \
	else \
		echo "No plan.json found. Run 'make plan-json' first."; \
	fi

# Terraform workflow: init, format, validate, and plan
tf-apply:
	terraform init
	terraform fmt -recursive
	terraform validate
	terraform plan -out=plan.out
	@echo "Run: aws-vault exec driftguard -- terraform apply plan.out"

# Apply core DriftGuard infrastructure (Step 4: auto-remediation)
apply-core:
	terraform init
	terraform fmt -recursive
	terraform validate
	terraform apply

# Destroy all DriftGuard infrastructure
destroy-core:
	terraform destroy
