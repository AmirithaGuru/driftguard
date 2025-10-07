# DriftGuard 🛡️

A guardrails-as-code platform for AWS that blocks risky Terraform changes at PR time and auto-remediates drift in production.

## 🎯 Goals

1. **Block risky Terraform changes** at PR time via CI security gates using Checkov + OPA/Rego
2. **Auto-remediate risky drift** in AWS quickly through CloudTrail → EventBridge → Lambda
3. **Produce comprehensive metrics** including PreventionRate, False-Positive %, MTTD, MTTR, CI overhead, and posture trends

## 🏗️ Architecture Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌─────────────┐
│   GitHub    │    │  AWS Cloud   │    │  DriftGuard │    │  Metrics &  │
│     PR      │───▶│   Drift      │───▶│  Remediate  │───▶│  Dashboard  │
│             │    │ Detection    │    │             │    │             │
└─────────────┘    └──────────────┘    └─────────────┘    └─────────────┘
       │
       ▼
┌─────────────┐
│  Checkov +  │
│ OPA/Rego    │
│  Security   │
│    Gate     │
└─────────────┘
```

## 🔧 Tech Stack

- **Infrastructure**: Terraform (AWS: IAM, S3, CloudTrail, GuardDuty, Security Hub, Lambda, EventBridge, CloudWatch)
- **CI/CD**: GitHub Actions with "security-checks" job
- **Security**: Checkov, OPA/Rego (Conftest)
- **Remediation**: Python (boto3)

## 📁 Project Structure

```
driftguard/
├── infra/           # Terraform infrastructure code
├── policy/          # OPA/Rego policies, tests, and exceptions
├── lambda/          # Python remediation functions
├── .github/workflows/ # GitHub Actions CI/CD
├── sim/             # Simulation scenarios for testing
├── metrics/         # Metrics collection and documentation
├── docs/            # Documentation and screenshots
└── README.md        # This file
```

## 🚀 Key Features

- **Prevention**: Block risky changes before they reach production
- **Detection**: Real-time monitoring of AWS resource drift
- **Remediation**: Automated fixes for common security issues
- **Metrics**: Comprehensive security posture tracking
- **Exceptions**: YAML-based allowlist with owner, reason, and expiration
- **Performance**: Fast CI checks (target ≤120s p95)

## 🛡️ Security Principles

- Least-privilege IAM for all Lambda functions and CI jobs
- Idempotent and reversible remediation actions
- Resource state verification before changes
- No permanent bypasses - all exceptions have expiration dates

## 🏷️ Resource Naming

- All AWS resources prefixed with `driftguard-*`
- All resources tagged with `project=driftguard, env=sandbox`

## 📊 Metrics Tracked

- **PreventionRate**: Percentage of risky changes blocked at PR time
- **False-Positive %**: Rate of incorrect security alerts
- **MTTD**: Mean Time To Detection of drift
- **MTTR**: Mean Time To Remediation
- **CI Overhead**: Time impact on CI/CD pipelines
- **Posture Trend**: Security posture improvement over time

## 🔄 Workflow

1. **PR Stage**: Terraform changes analyzed by Checkov + OPA/Rego policies
2. **Production**: CloudTrail events monitored for risky changes
3. **Detection**: EventBridge triggers on security-relevant events
4. **Remediation**: Python Lambda functions auto-fix common issues
5. **Metrics**: CloudWatch collects and analyzes security metrics

## 📖 Getting Started

See individual folders for detailed setup instructions:
- `infra/` - Deploy the DriftGuard infrastructure
- `policy/` - Configure security policies
- `lambda/` - Set up remediation functions
- `.github/workflows/` - Configure CI security gates

---

*DriftGuard: Your AWS infrastructure's security guardian* 🛡️
