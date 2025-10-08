# DriftGuard Documentation Assets

This directory contains screenshots and diagrams for the DriftGuard README and documentation.

## Screenshot Placeholders

The following screenshots should be captured during demo runs:

### 1. `pr-fail.png`
**Capture**: GitHub Actions CI workflow showing a failed security check

**What to show**:
- Failed status indicator on pull request
- Conftest output showing policy violation (e.g., "Security Group allows 0.0.0.0/0 on port 22")
- Checkov findings highlighting High/Critical issues
- Pull request merge blocked by required status check

**How to capture**:
1. Create a branch with a risky Terraform change (e.g., open security group)
2. Push to GitHub to trigger CI workflow
3. Navigate to the PR and click on "Details" for the failed check
4. Screenshot the workflow output showing the policy denial

---

### 2. `exception-waiver.png`
**Capture**: GitHub Actions CI workflow showing a passing check with policy exception

**What to show**:
- Passing status indicator on pull request
- Conftest output mentioning exception ID (e.g., "EX-DEMO-001")
- Warning message about time-boxed waiver
- Pull request allowed to merge with exception noted

**How to capture**:
1. Add an exception to `policy/exceptions.yaml`
2. Create matching Terraform resource with exception ID
3. Push to GitHub and screenshot the passing workflow
4. Capture the workflow log showing the exception being applied

---

### 3. `lambda-logs.png`
**Capture**: CloudWatch Logs showing structured JSON remediation logs

**What to show**:
- Lambda function logs in CloudWatch console
- Structured JSON log entries with fields:
  - `"level": "INFO"`
  - `"message": "S3 remediation completed"` or `"SG remediation completed"`
  - `"bucket": "..."` or `"security_group_id": "..."`
  - `"actions": ["PAB_enabled", "policy_sanitized"]`
  - `"latency_ms": 8234`
- Timestamp showing near real-time response (< 60s)

**How to capture**:
1. Simulate drift (make an S3 bucket public or add open SG rule)
2. Wait ~30-60 seconds for Lambda to execute
3. Navigate to CloudWatch Logs console
4. Open log stream for `/aws/lambda/driftguard-remediator`
5. Screenshot the JSON log entries showing remediation

---

### 4. `metrics-table.png`
**Capture**: KPI metrics from metrics.md or CloudWatch dashboard

**What to show**:
- Markdown table from `metrics/metrics.md` showing:
  - Prevention Rate: X% (blocked/total)
  - False-Positive %: X%
  - CI Overhead p50/p95
  - MTTD p50/p95
  - MTTR p50/p95
  - Security Density change

**Alternative**: CloudWatch dashboard with custom metrics:
- Line charts for `RemediationLatencyMs` (p50/p95)
- Bar chart for `RemediationSuccess` vs `RemediationFailure` counts
- Time series showing trend over multiple drift simulations

**How to capture**:
1. After running multiple drift simulations, run `python3 metrics/collect.py`
2. Screenshot the generated `metrics.md` table
3. Or create a CloudWatch dashboard and screenshot the metrics charts

---

### 5. `security-hub-finding.png` (Optional)
**Capture**: AWS Security Hub console showing DriftGuard findings

**What to show**:
- Security Hub findings list filtered for DriftGuard
- Finding details showing:
  - Title: "DriftGuard: Auto-remediated ..."
  - Severity: Medium/High
  - Compliance status: PASSED (after remediation)
  - Resource details (bucket name, SG ID)
  - Remediation timestamp

**How to capture**:
1. Ensure `ENABLE_SECURITY_HUB=true` in Lambda environment variables
2. Simulate drift and wait for remediation
3. Navigate to Security Hub console
4. Filter findings by "DriftGuard" or by resource ID
5. Screenshot the finding details

---

## How to Add Screenshots

1. Capture screenshots following the guides above
2. Name files exactly as listed (lowercase, hyphens)
3. Save as PNG format (recommended resolution: 1920x1080 or higher)
4. Optimize file size if needed (use tools like `pngquant` or online compressors)
5. Place files directly in this `/docs/` directory
6. Update README.md to reference screenshots using relative paths

## Architecture Diagrams

Additional diagrams can be added here:
- `architecture-detailed.png`: Expanded architecture with all AWS services
- `policy-flow.png`: Flowchart of policy evaluation logic
- `remediation-flow.png`: Sequence diagram for drift detection → remediation

These can be created using tools like:
- **Draw.io** (free, web-based)
- **Lucidchart** (collaborative diagramming)
- **PlantUML** (text-based UML diagrams)
- **Mermaid** (Markdown-native diagrams)

---

**Note**: All screenshots should be captured in a sandbox AWS account with no sensitive data visible. Account IDs, resource names, and other identifying information can be sanitized if needed.
