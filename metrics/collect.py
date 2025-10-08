#!/usr/bin/env python3
"""
DriftGuard Metrics Collector

Collects and analyzes metrics from CI runs, drift simulations, and Checkov scans
to generate KPI reports for the DriftGuard platform.

Input Files (in /metrics/input/):
- ci_runs.json: CI results from GitHub Actions security checks
- drift_timestamps.csv: Timestamp data from drift simulation drills
- cloudwatch_logs.jsonl: Alternative CloudWatch log exports
- checkov_baseline.json: Checkov scan results before security gates
- checkov_post.json: Checkov scan results after security gates
- loc.json: Optional LOC data for density calculations

Output:
- metrics.md: Markdown report with KPI table and trend analysis
- density_trend.png: Optional trend chart (if matplotlib available)

Usage:
    python collect.py                           # Generate metrics report
    python collect.py --init-samples           # Create sample input files
    python collect.py --out custom/metrics.md  # Custom output path
"""

import argparse
import csv
import json
import logging
import os
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Constants
DEFAULT_INPUT_DIR = Path("input")
DEFAULT_OUTPUT_FILE = Path("metrics.md")
DEFAULT_CHART_FILE = Path("density_trend.png")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Try to import matplotlib for optional charting
try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.info("matplotlib not available - skipping trend chart generation")


def read_json(path: Path) -> Optional[Union[Dict, List]]:
    """Read JSON file and return parsed data or None if file doesn't exist."""
    if not path.exists():
        logger.warning(f"File not found: {path}")
        return None
    
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error reading {path}: {e}")
        return None


def read_jsonl(path: Path) -> Optional[List[Dict]]:
    """Read JSONL file and return list of parsed JSON objects."""
    if not path.exists():
        logger.warning(f"File not found: {path}")
        return None
    
    try:
        data = []
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    data.append(json.loads(line))
        return data
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error reading {path}: {e}")
        return None


def read_csv(path: Path) -> Optional[List[Dict]]:
    """Read CSV file and return list of dictionaries."""
    if not path.exists():
        logger.warning(f"File not found: {path}")
        return None
    
    try:
        data = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            data = list(reader)
        return data
    except IOError as e:
        logger.error(f"Error reading {path}: {e}")
        return None


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely divide two numbers, returning default if denominator is zero."""
    return numerator / denominator if denominator != 0 else default


def p50_p95(values: List[float]) -> Tuple[float, float]:
    """Calculate 50th and 95th percentiles."""
    if not values:
        return 0.0, 0.0
    values_sorted = sorted(values)
    n = len(values_sorted)
    p50_idx = int(0.5 * n)
    p95_idx = int(0.95 * n)
    p50_idx = min(p50_idx, n - 1)
    p95_idx = min(p95_idx, n - 1)
    return values_sorted[p50_idx], values_sorted[p95_idx]


def parse_iso_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 timestamp string to datetime object."""
    if not ts_str:
        return None
    
    try:
        # Handle various ISO formats
        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        # Fallback for more flexible parsing
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        logger.warning(f"Could not parse timestamp: {ts_str}")
        return None


def seconds_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    """Calculate seconds between two timestamps."""
    if not start or not end:
        return None
    delta = end - start
    return delta.total_seconds()


def compute_prevention_and_fp(ci_runs: List[Dict]) -> Tuple[float, float, int, int, int, int]:
    """
    Compute prevention rate and false positive rate from CI runs.
    
    Returns: (prevention_rate, false_positive_rate, bad_total, bad_blocked, good_total, good_failed)
    """
    if not ci_runs:
        return 0.0, 0.0, 0, 0, 0, 0
    
    bad_total = sum(1 for run in ci_runs if run.get('is_bad', False))
    bad_blocked = sum(1 for run in ci_runs if run.get('is_bad', False) and run.get('status') == 'failed')
    
    good_total = sum(1 for run in ci_runs if not run.get('is_bad', False))
    good_failed = sum(1 for run in ci_runs if not run.get('is_bad', False) and run.get('status') == 'failed')
    
    prevention_rate = safe_divide(bad_blocked, bad_total)
    false_positive_rate = safe_divide(good_failed, good_total)
    
    return prevention_rate, false_positive_rate, bad_total, bad_blocked, good_total, good_failed


def compute_ci_overhead(ci_runs: List[Dict]) -> Tuple[float, float]:
    """Compute CI overhead percentiles from security-checks job durations."""
    durations = []
    for run in ci_runs:
        if run.get('job') == 'security-checks' and run.get('duration_sec'):
            try:
                durations.append(float(run['duration_sec']))
            except (ValueError, TypeError):
                continue
    
    return p50_p95(durations)


def compute_mttd_mttr(drift_rows: List[Dict], cw_logs: Optional[List[Dict]] = None) -> Tuple[List[float], List[float], float, float, float, float]:
    """
    Compute MTTD and MTTR from drift simulation data.
    
    Returns: (mttd_values, mttr_values, mttd_p50, mttd_p95, mttr_p50, mttr_p95)
    """
    mttd_values = []
    mttr_values = []
    
    if drift_rows:
        # Use drift_timestamps.csv data
        for row in drift_rows:
            t0 = parse_iso_timestamp(row.get('t0'))
            t1 = parse_iso_timestamp(row.get('t1'))
            t2 = parse_iso_timestamp(row.get('t2'))
            t3 = parse_iso_timestamp(row.get('t3'))
            
            if t0 and t1:
                mttd = seconds_between(t0, t1)
                if mttd is not None:
                    mttd_values.append(mttd)
            
            if t1 and t3:
                mttr = seconds_between(t1, t3)
                if mttr is not None:
                    mttr_values.append(mttr)
    
    elif cw_logs:
        # Parse CloudWatch logs to extract timestamps
        logger.info("Parsing CloudWatch logs for MTTD/MTTR calculation...")
        
        # Group logs by case/request ID to find invoke->remediation windows
        invoke_times = {}
        remediation_times = {}
        
        for log in cw_logs:
            try:
                ts = parse_iso_timestamp(log.get('timestamp'))
                message = log.get('message', '')
                
                # Try to parse structured JSON from message
                try:
                    msg_data = json.loads(message)
                    msg_type = msg_data.get('message', '')
                    
                    if 'Processing CloudTrail event' in msg_type:
                        # This is an invoke event (t1)
                        invoke_times[log.get('logStream', 'unknown')] = ts
                    elif 'remediation completed' in msg_type or 'remediation failed' in msg_type:
                        # This is a completion event (t3)
                        remediation_times[log.get('logStream', 'unknown')] = ts
                
                except json.JSONDecodeError:
                    # Not structured JSON, check for patterns in raw message
                    if 'Processing CloudTrail event' in message:
                        invoke_times[log.get('logStream', 'unknown')] = ts
                    elif 'remediation completed' in message or 'remediation failed' in message:
                        remediation_times[log.get('logStream', 'unknown')] = ts
            
            except Exception as e:
                logger.debug(f"Error processing log entry: {e}")
                continue
        
        # Match invoke and remediation times
        for stream_id, invoke_time in invoke_times.items():
            remediation_time = remediation_times.get(stream_id)
            if remediation_time:
                mttr = seconds_between(invoke_time, remediation_time)
                if mttr is not None:
                    mttr_values.append(mttr)
    
    mttd_p50, mttd_p95 = p50_p95(mttd_values)
    mttr_p50, mttr_p95 = p50_p95(mttr_values)
    
    return mttd_values, mttr_values, mttd_p50, mttd_p95, mttr_p50, mttr_p95


def count_checkov_severities(checkov_data: Dict) -> int:
    """Count High and Critical severity findings in Checkov results."""
    if not checkov_data:
        return 0
    
    try:
        results = checkov_data.get('results', {})
        failed_checks = results.get('failed_checks', [])
        
        count = 0
        for check in failed_checks:
            severity = check.get('check_result', {}).get('result', {}).get('severity', '').lower()
            if severity in ['high', 'critical']:
                count += 1
        
        return count
    except (KeyError, TypeError):
        logger.warning("Could not parse Checkov data structure")
        return 0


def compute_density_change(checkov_base: Dict, checkov_post: Dict, kloc: Optional[float] = None) -> Tuple[float, float, float]:
    """
    Compute density change between baseline and post-gate Checkov scans.
    
    Returns: (base_density, post_density, delta)
    """
    base_count = count_checkov_severities(checkov_base)
    post_count = count_checkov_severities(checkov_post)
    
    if kloc and kloc > 0:
        # Density per KLOC
        base_density = safe_divide(base_count, kloc)
        post_density = safe_divide(post_count, kloc)
    else:
        # Fallback: estimate resources and use per-100-resources density
        base_resources = estimate_resource_count(checkov_base)
        post_resources = estimate_resource_count(checkov_post)
        
        base_density = safe_divide(base_count, base_resources / 100)
        post_density = safe_divide(post_count, post_resources / 100)
    
    delta = post_density - base_density
    return base_density, post_density, delta


def estimate_resource_count(checkov_data: Dict) -> int:
    """Estimate resource count from Checkov data structure."""
    if not checkov_data:
        return 100  # Default fallback
    
    try:
        results = checkov_data.get('results', {})
        failed_checks = results.get('failed_checks', [])
        
        # Count unique resource IDs
        resource_ids = set()
        for check in failed_checks:
            resource_id = check.get('check_result', {}).get('resource', '')
            if resource_id:
                resource_ids.add(resource_id)
        
        return max(len(resource_ids), 1)  # Ensure at least 1
    except (KeyError, TypeError):
        return 100  # Default fallback


def maybe_plot_density(ci_runs: List[Dict], output_path: Path) -> bool:
    """Generate density trend chart if matplotlib is available and we have enough data."""
    if not MATPLOTLIB_AVAILABLE:
        logger.info("Skipping trend chart - matplotlib not available")
        return False
    
    if not ci_runs:
        logger.info("Skipping trend chart - no CI run data")
        return False
    
    # Extract commit timestamps and create daily buckets
    daily_buckets = {}
    for run in ci_runs:
        commit_ts = run.get('commit_ts')
        if commit_ts:
            dt = parse_iso_timestamp(commit_ts)
            if dt:
                day_key = dt.date()
                if day_key not in daily_buckets:
                    daily_buckets[day_key] = []
                daily_buckets[day_key].append(run)
    
    if len(daily_buckets) < 2:
        logger.info("Skipping trend chart - need at least 2 days of data")
        return False
    
    try:
        dates = sorted(daily_buckets.keys())
        density_values = []
        
        for date in dates:
            runs = daily_buckets[date]
            bad_runs = [r for r in runs if r.get('is_bad', False)]
            total_runs = len(runs)
            
            if total_runs > 0:
                # Calculate "density" as ratio of bad PRs (simplified metric)
                density = len(bad_runs) / total_runs
                density_values.append(density)
            else:
                density_values.append(0)
        
        # Create plot
        plt.figure(figsize=(10, 6))
        plt.plot(dates, density_values, marker='o', linewidth=2, markersize=6)
        plt.title('DriftGuard Policy Violation Density Trend')
        plt.xlabel('Date')
        plt.ylabel('Violation Density (Bad PRs / Total PRs)')
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        
        # Format x-axis
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=1))
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Trend chart saved to {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error generating trend chart: {e}")
        return False


def assemble_report(ci_runs: List[Dict], drift_rows: List[Dict], cw_logs: Optional[List[Dict]], 
                   checkov_base: Dict, checkov_post: Dict, kloc: Optional[float],
                   input_files_used: List[str]) -> str:
    """Assemble the complete metrics report in Markdown format."""
    
    # Compute all KPIs
    prevention_rate, fp_rate, bad_total, bad_blocked, good_total, good_failed = compute_prevention_and_fp(ci_runs)
    ci_p50, ci_p95 = compute_ci_overhead(ci_runs)
    mttd_values, mttr_values, mttd_p50, mttd_p95, mttr_p50, mttr_p95 = compute_mttd_mttr(drift_rows, cw_logs)
    base_density, post_density, density_delta = compute_density_change(checkov_base, checkov_post, kloc)
    
    # Format values
    def format_percent(value: float) -> str:
        return f"{value:.1%}" if value > 0 else "N/A"
    
    def format_seconds(value: float) -> str:
        return f"{value:.1f}" if value > 0 else "N/A"
    
    def format_density(value: float) -> str:
        return f"{value:.2f}" if value >= 0 else "N/A"
    
    # Generate report
    report = f"""# DriftGuard Metrics Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## Key Performance Indicators

| KPI | Value |
|-----|-------|
| **Prevention Rate** | {format_percent(prevention_rate)} ({bad_blocked}/{bad_total}) |
| **False-Positive %** | {format_percent(fp_rate)} ({good_failed}/{good_total}) |
| **CI Overhead p50/p95 (s)** | {format_seconds(ci_p50)} / {format_seconds(ci_p95)} |
| **MTTD p50/p95 (s)** | {format_seconds(mttd_p50)} / {format_seconds(mttd_p95)} |
| **MTTR p50/p95 (s)** | {format_seconds(mttr_p50)} / {format_seconds(mttr_p95)} |
| **High/Critical Density** | {format_density(base_density)} → {format_density(post_density)} ({density_delta:+.2f}) |

## Notes

- **Time Window**: Based on available data from input files
- **Files Used**: {', '.join(input_files_used) if input_files_used else 'None'}
- **MTTD**: Mean Time To Detection (Event observed - Change made)
- **MTTR**: Mean Time To Remediation (Remediation completion - Event observed)
- **Density**: High/Critical findings per KLOC or per 100 resources

## Data Quality

- **CI Runs**: {len(ci_runs)} total runs analyzed
- **Drift Simulations**: {len(mttd_values)} MTTD measurements, {len(mttr_values)} MTTR measurements
- **Checkov Scans**: Baseline and post-gate comparison available

"""
    
    return report


def create_sample_files(input_dir: Path) -> None:
    """Create sample input files for demonstration."""
    input_dir.mkdir(exist_ok=True)
    
    # Sample CI runs
    sample_ci_runs = [
        {
            "pr_id": "PR-001",
            "is_bad": True,
            "status": "failed",
            "job": "security-checks",
            "duration_sec": 42.1,
            "commit_ts": "2025-10-06T12:34:56Z"
        },
        {
            "pr_id": "PR-002", 
            "is_bad": False,
            "status": "passed",
            "job": "security-checks",
            "duration_sec": 38.7,
            "commit_ts": "2025-10-06T14:22:10Z"
        },
        {
            "pr_id": "PR-003",
            "is_bad": True,
            "status": "failed", 
            "job": "security-checks",
            "duration_sec": 45.3,
            "commit_ts": "2025-10-07T09:15:33Z"
        }
    ]
    
    with open(input_dir / "ci_runs.json", 'w') as f:
        json.dump(sample_ci_runs, f, indent=2)
    
    # Sample drift timestamps
    sample_drift_data = [
        {
            "case": "S3_ACL_001",
            "t0": "2025-10-06T15:30:00.000Z",
            "t1": "2025-10-06T15:30:45.123Z", 
            "t2": "2025-10-06T15:30:46.456Z",
            "t3": "2025-10-06T15:31:12.789Z"
        },
        {
            "case": "SG_SSH_001",
            "t0": "2025-10-06T16:45:00.000Z",
            "t1": "2025-10-06T16:45:38.234Z",
            "t2": "2025-10-06T16:45:39.567Z", 
            "t3": "2025-10-06T16:46:05.890Z"
        }
    ]
    
    with open(input_dir / "drift_timestamps.csv", 'w', newline='') as f:
        if sample_drift_data:
            writer = csv.DictWriter(f, fieldnames=sample_drift_data[0].keys())
            writer.writeheader()
            writer.writerows(sample_drift_data)
    
    # Sample Checkov baseline
    sample_checkov_base = {
        "results": {
            "failed_checks": [
                {
                    "check_result": {
                        "result": {"severity": "High"},
                        "resource": "aws_s3_bucket.test_bucket"
                    }
                },
                {
                    "check_result": {
                        "result": {"severity": "Critical"}, 
                        "resource": "aws_security_group.test_sg"
                    }
                }
            ]
        }
    }
    
    with open(input_dir / "checkov_baseline.json", 'w') as f:
        json.dump(sample_checkov_base, f, indent=2)
    
    # Sample Checkov post-gate (fewer issues)
    sample_checkov_post = {
        "results": {
            "failed_checks": [
                {
                    "check_result": {
                        "result": {"severity": "Medium"},
                        "resource": "aws_iam_policy.test_policy"
                    }
                }
            ]
        }
    }
    
    with open(input_dir / "checkov_post.json", 'w') as f:
        json.dump(sample_checkov_post, f, indent=2)
    
    # Sample LOC data
    sample_loc = {"kloc": 12.5}
    with open(input_dir / "loc.json", 'w') as f:
        json.dump(sample_loc, f, indent=2)
    
    logger.info(f"Sample files created in {input_dir}/")
    logger.info("Files created:")
    logger.info("  - ci_runs.json (3 sample CI runs)")
    logger.info("  - drift_timestamps.csv (2 sample drift measurements)")  
    logger.info("  - checkov_baseline.json (sample baseline scan)")
    logger.info("  - checkov_post.json (sample post-gate scan)")
    logger.info("  - loc.json (sample LOC data)")


def main():
    parser = argparse.ArgumentParser(description="DriftGuard Metrics Collector")
    parser.add_argument("--init-samples", action="store_true", 
                       help="Create sample input files for demonstration")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT_FILE,
                       help=f"Output file path (default: {DEFAULT_OUTPUT_FILE})")
    
    args = parser.parse_args()
    
    # Initialize input directory
    input_dir = Path(__file__).parent / DEFAULT_INPUT_DIR
    
    if args.init_samples:
        create_sample_files(input_dir)
        return
    
    # Ensure input directory exists
    input_dir.mkdir(exist_ok=True)
    
    # Load available input files
    logger.info(f"Loading data from {input_dir}/")
    
    ci_runs = read_json(input_dir / "ci_runs.json") or []
    drift_rows = read_csv(input_dir / "drift_timestamps.csv") or []
    cw_logs = read_jsonl(input_dir / "cloudwatch_logs.jsonl")
    checkov_base = read_json(input_dir / "checkov_baseline.json")
    checkov_post = read_json(input_dir / "checkov_post.json")
    loc_data = read_json(input_dir / "loc.json")
    kloc = loc_data.get("kloc") if loc_data else None
    
    # Track which files were used
    input_files_used = []
    if ci_runs:
        input_files_used.append("ci_runs.json")
    if drift_rows:
        input_files_used.append("drift_timestamps.csv")
    elif cw_logs:
        input_files_used.append("cloudwatch_logs.jsonl")
    if checkov_base:
        input_files_used.append("checkov_baseline.json")
    if checkov_post:
        input_files_used.append("checkov_post.json")
    if kloc:
        input_files_used.append("loc.json")
    
    if not input_files_used:
        logger.error("No input files found! Use --init-samples to create sample files.")
        return
    
    # Generate trend chart if possible
    chart_created = False
    if ci_runs:
        chart_path = Path(__file__).parent / DEFAULT_CHART_FILE
        chart_created = maybe_plot_density(ci_runs, chart_path)
    
    # Assemble and write report
    report = assemble_report(ci_runs, drift_rows, cw_logs, checkov_base, checkov_post, kloc, input_files_used)
    
    output_path = Path(__file__).parent / args.out
    with open(output_path, 'w') as f:
        f.write(report)
    
    logger.info(f"Metrics report written to {output_path}")
    if chart_created:
        logger.info(f"Trend chart written to {chart_path}")
    
    # Print runbook summary
    print("\n" + "="*60)
    print("DRIFTGUARD METRICS COLLECTOR - RUNBOOK")
    print("="*60)
    print(f"Input directory: {input_dir}")
    print(f"Output file: {output_path}")
    print(f"Files processed: {', '.join(input_files_used)}")
    print(f"Chart generated: {'Yes' if chart_created else 'No'}")
    print("\nTo run:")
    print("  python collect.py                    # Generate metrics")
    print("  python collect.py --init-samples     # Create sample files")
    print("  python collect.py --out custom.md    # Custom output")
    print("\nInput file formats documented in script header comments.")


if __name__ == "__main__":
    main()
