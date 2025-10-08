# DriftGuard Metrics Report

Generated: 2025-10-07 19:51:13 UTC

## Key Performance Indicators

| KPI | Value |
|-----|-------|
| **Prevention Rate** | 100.0% (2/2) |
| **False-Positive %** | N/A (0/1) |
| **CI Overhead p50/p95 (s)** | 42.1 / 45.3 |
| **MTTD p50/p95 (s)** | 45.1 / 45.1 |
| **MTTR p50/p95 (s)** | 27.7 / 27.7 |
| **High/Critical Density** | 0.16 → 0.00 (-0.16) |

## Notes

- **Time Window**: Based on available data from input files
- **Files Used**: ci_runs.json, drift_timestamps.csv, checkov_baseline.json, checkov_post.json, loc.json
- **MTTD**: Mean Time To Detection (Event observed - Change made)
- **MTTR**: Mean Time To Remediation (Remediation completion - Event observed)
- **Density**: High/Critical findings per KLOC or per 100 resources

## Data Quality

- **CI Runs**: 3 total runs analyzed
- **Drift Simulations**: 2 MTTD measurements, 2 MTTR measurements
- **Checkov Scans**: Baseline and post-gate comparison available

