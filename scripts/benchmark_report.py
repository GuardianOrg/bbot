#!/usr/bin/env python3
"""
Branch-based benchmark comparison tool for BBOT performance tests.

This script takes two git branches, runs benchmarks on each, and generates
a comparison report showing performance differences between them.
"""

import json
import argparse
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


def run_command(cmd: List[str], cwd: Path = None, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(
            cmd, 
            cwd=cwd, 
            capture_output=capture_output, 
            text=True, 
            check=True
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}")
        print(f"Exit code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        raise


def get_current_branch() -> str:
    """Get the current git branch name."""
    result = run_command(["git", "branch", "--show-current"])
    return result.stdout.strip()


def checkout_branch(branch: str, repo_path: Path = None):
    """Checkout a git branch."""
    print(f"Checking out branch: {branch}")
    run_command(["git", "checkout", branch], cwd=repo_path)


def run_benchmarks(output_file: Path, repo_path: Path = None) -> bool:
    """Run benchmarks and save results to JSON file."""
    print(f"Running benchmarks, saving to {output_file}")
    try:
        cmd = [
            "poetry", "run", "python", "-m", "pytest", 
            "bbot/test/benchmarks/", 
            "--benchmark-only", 
            f"--benchmark-json={output_file}",
            "-q"
        ]
        run_command(cmd, cwd=repo_path, capture_output=False)
        return True
    except subprocess.CalledProcessError:
        print(f"Benchmarks failed for current state")
        return False


def load_benchmark_data(filepath: Path) -> Dict[str, Any]:
    """Load benchmark data from JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Benchmark file not found: {filepath}")
        return {}
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON from {filepath}")
        return {}


def format_time(seconds: float) -> str:
    """Format time in human-readable format."""
    if seconds < 0.001:
        return f"{seconds * 1000000:.1f}µs"
    elif seconds < 1:
        return f"{seconds * 1000:.2f}ms"
    else:
        return f"{seconds:.3f}s"


def format_ops(ops: float) -> str:
    """Format operations per second."""
    if ops > 1000:
        return f"{ops/1000:.1f}K ops/sec"
    else:
        return f"{ops:.1f} ops/sec"


def calculate_change_percentage(old_value: float, new_value: float) -> Tuple[float, str]:
    """Calculate percentage change and return emoji indicator."""
    if old_value == 0:
        return 0, "🆕"
    
    change = ((new_value - old_value) / old_value) * 100
    
    if change > 5:
        return change, "⚠️"  # Regression (slower)
    elif change < -5:
        return change, "🚀"  # Improvement (faster)
    else:
        return change, "✅"  # No significant change


def generate_benchmark_table(benchmarks: List[Dict[str, Any]], title: str = "Results") -> str:
    """Generate markdown table for benchmark results."""
    if not benchmarks:
        return f"### {title}\nNo benchmark data available.\n"
    
    table = f"""### {title}

| Test Name | Mean Time | Ops/sec | Min | Max |
|-----------|-----------|---------|-----|-----|
"""
    
    for bench in benchmarks:
        stats = bench.get('stats', {})
        name = bench.get('name', 'Unknown').replace('test_bloom_filter_', '')
        mean = format_time(stats.get('mean', 0))
        ops = format_ops(stats.get('ops', 0))
        min_time = format_time(stats.get('min', 0))
        max_time = format_time(stats.get('max', 0))
        
        table += f"| {name} | {mean} | {ops} | {min_time} | {max_time} |\n"
    
    return table + "\n"


def generate_comparison_table(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate comparison table between current and base benchmark results."""
    if not current_data or not base_data:
        return ""
    
    current_benchmarks = current_data.get('benchmarks', [])
    base_benchmarks = base_data.get('benchmarks', [])
    
    # Create lookup for base benchmarks
    base_lookup = {bench['name']: bench for bench in base_benchmarks}
    
    if not current_benchmarks:
        return ""
    
    table = f"""## 📊 Performance Comparison: `{base_branch}` → `{current_branch}`

| Test Name | {base_branch} | {current_branch} | Change | Status |
|-----------|---------|----------|--------|--------|
"""
    
    significant_changes = []
    
    for current_bench in current_benchmarks:
        name = current_bench.get('name', 'Unknown')
        test_name = name.replace('test_bloom_filter_', '')
        
        current_stats = current_bench.get('stats', {})
        current_mean = current_stats.get('mean', 0)
        
        base_bench = base_lookup.get(name)
        if base_bench:
            base_stats = base_bench.get('stats', {})
            base_mean = base_stats.get('mean', 0)
            
            change_percent, emoji = calculate_change_percentage(base_mean, current_mean)
            
            table += f"| {test_name} | {format_time(base_mean)} | {format_time(current_mean)} | {change_percent:+.1f}% | {emoji} |\n"
            
            # Track significant changes
            if abs(change_percent) > 5:
                direction = "slower" if change_percent > 0 else "faster"
                significant_changes.append(f"- **{test_name}**: {abs(change_percent):.1f}% {direction}")
        else:
            table += f"| {test_name} | - | {format_time(current_mean)} | New | 🆕 |\n"
            significant_changes.append(f"- **{test_name}**: New test")
    
    # Add summary of significant changes
    if significant_changes:
        table += f"\n### 🔍 Significant Changes (>5%)\n"
        table += "\n".join(significant_changes)
        table += "\n"
    else:
        table += "\n✅ **No significant performance changes detected**\n"
    
    return table + "\n"


def generate_report(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate complete benchmark comparison report."""
    
    # Start building report
    report = f"## 🚀 Performance Benchmark Report\n\n"
    report += f"Comparing performance between `{base_branch}` (baseline) and `{current_branch}` (current).\n\n"
    
    if not current_data:
        report += "⚠️ No current benchmark data available.\n"
        return report
    
    if not base_data:
        report += "⚠️ No baseline benchmark data available. Showing current results only.\n\n"
        current_benchmarks = current_data.get('benchmarks', [])
        if current_benchmarks:
            report += generate_benchmark_table(current_benchmarks, f"Current Results ({current_branch})")
    else:
        # Add comparison
        comparison = generate_comparison_table(current_data, base_data, current_branch, base_branch)
        if comparison:
            report += comparison
    
    # Add environment info
    machine_info = current_data.get('machine_info', {})
    commit_info = current_data.get('commit_info', {})
    
    report += "### 🖥️ Test Environment\n"
    report += f"- **Python**: {machine_info.get('python_version', 'Unknown')}\n"
    report += f"- **Platform**: {machine_info.get('platform', 'Unknown')}\n"
    report += f"- **CPU**: {machine_info.get('processor', 'Unknown')}\n"
    
    if commit_info:
        report += f"- **Commit**: `{commit_info.get('id', 'Unknown')[:8]}`\n"
    
    report += "\n*Benchmarks measure bloom filter operations critical for DNS brute-forcing performance.*\n"
    
    return report


def main():
    parser = argparse.ArgumentParser(description="Compare benchmark performance between git branches")
    parser.add_argument("--base", required=True, help="Base branch name (e.g., 'main', 'dev')")
    parser.add_argument("--current", required=True, help="Current branch name (e.g., 'feature-branch', 'HEAD')")
    parser.add_argument("--output", type=Path, help="Output markdown file (default: stdout)")
    parser.add_argument("--keep-results", action="store_true", help="Keep intermediate JSON files")
    
    args = parser.parse_args()
    
    # Get current working directory
    repo_path = Path.cwd()
    
    # Save original branch to restore later
    try:
        original_branch = get_current_branch()
        print(f"Current branch: {original_branch}")
    except subprocess.CalledProcessError:
        print("Warning: Could not determine current branch")
        original_branch = None
    
    # Create temporary files for benchmark results
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        base_results_file = temp_path / "base_results.json"
        current_results_file = temp_path / "current_results.json"
        
        base_data = {}
        current_data = {}
        
        try:
            # Run benchmarks on base branch
            print(f"\n=== Running benchmarks on base branch: {args.base} ===")
            checkout_branch(args.base, repo_path)
            if run_benchmarks(base_results_file, repo_path):
                base_data = load_benchmark_data(base_results_file)
            
            # Run benchmarks on current branch
            print(f"\n=== Running benchmarks on current branch: {args.current} ===")
            checkout_branch(args.current, repo_path)
            if run_benchmarks(current_results_file, repo_path):
                current_data = load_benchmark_data(current_results_file)
            
            # Generate report
            print(f"\n=== Generating comparison report ===")
            report = generate_report(current_data, base_data, args.current, args.base)
            
            # Output report
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"Report written to {args.output}")
            else:
                print("\n" + "="*80)
                print(report)
            
            # Keep results if requested
            if args.keep_results:
                if base_data:
                    with open("base_benchmark_results.json", 'w') as f:
                        json.dump(base_data, f, indent=2)
                if current_data:
                    with open("current_benchmark_results.json", 'w') as f:
                        json.dump(current_data, f, indent=2)
                print("Benchmark result files saved.")
            
        finally:
            # Restore original branch
            if original_branch:
                print(f"\nRestoring original branch: {original_branch}")
                try:
                    checkout_branch(original_branch, repo_path)
                except subprocess.CalledProcessError:
                    print(f"Warning: Could not restore original branch {original_branch}")


if __name__ == "__main__":
    main() 