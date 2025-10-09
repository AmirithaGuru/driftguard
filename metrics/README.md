# DriftGuard Metrics Collection

This module collects and analyzes metrics from the DriftGuard platform to generate KPI reports for
security posture monitoring and performance tracking.

## Quick Start

```bash
# Create sample data and generate your first report
python3 collect.py --init-samples
python3 collect.py

# View the generated report
cat metrics.md
```

## Features

- **CI Performance Analysis**: Prevention rates, false positives, and CI overhead
- **Drift Detection Metrics**: MTTD (Mean Time To Detection) and MTTR (Mean Time To Remediation)
- **Security Density Tracking**: High/Critical finding density changes over time
- **Trend Visualization**: Optional PNG charts (requires matplotlib)
- **Robust Error Handling**: Graceful degradation when input files are missing

## Input Files

Place your data files in `/metrics/input/`:

| File                    | Purpose                     | Format       |
| ----------------------- | --------------------------- | ------------ |
| `ci_runs.json`          | GitHub Actions CI results   | JSON array   |
| `drift_timestamps.csv`  | Drift simulation timestamps | CSV          |
| `cloudwatch_logs.jsonl` | CloudWatch log exports      | JSON Lines   |
| `checkov_baseline.json` | Pre-gate Checkov scan       | Checkov JSON |
| `checkov_post.json`     | Post-gate Checkov scan      | Checkov JSON |
| `loc.json`              | Lines of code data          | JSON         |

## Output

- **`metrics.md`**: KPI report with summary table and analysis notes
- **`density_trend.png`**: Optional trend chart (if matplotlib available)

## Usage

```bash
# Generate metrics report
python3 collect.py

# Create sample input files for testing
python3 collect.py --init-samples

# Custom output location
python3 collect.py --out custom/metrics.md
```

## KPI Definitions

- **Prevention Rate**: Percentage of bad PRs that were blocked by CI gates
- **False-Positive Rate**: Percentage of good PRs incorrectly flagged by CI
- **CI Overhead**: Time spent running security checks (p50/p95 percentiles)
- **MTTD**: Time from risky change to detection by EventBridge
- **MTTR**: Time from detection to successful remediation
- **Security Density**: High/Critical findings per KLOC or per 100 resources

## Integration

This tool is designed to integrate with:

- GitHub Actions CI/CD pipelines
- DriftGuard Step 5 simulation playbooks
- Checkov security scanning workflows
- CloudWatch log aggregation systems
