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
    
    # Check if benchmarks directory exists
    benchmarks_dir = repo_path / "bbot/test/benchmarks" if repo_path else Path("bbot/test/benchmarks")
    if not benchmarks_dir.exists():
        print(f"Benchmarks directory not found: {benchmarks_dir}")
        print("This branch likely doesn't have benchmark tests yet.")
        return False
    
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
    
    # Count changes for summary
    improvements = 0
    regressions = 0
    no_change = 0
    
    table = f"""## 📊 Performance Benchmark Results

> Comparing **`{base_branch}`** (baseline) vs **`{current_branch}`** (current)

<details>
<summary>📈 <strong>Detailed Results</strong></summary>

| 🧪 Test Name | 📏 Base | 📏 Current | 📈 Change | 🎯 Status |
|--------------|---------|------------|-----------|-----------|"""
    
    significant_changes = []
    performance_summary = []
    
    for current_bench in current_benchmarks:
        name = current_bench.get('name', 'Unknown')
        test_name = name.replace('test_bloom_filter_', '').replace('_', ' ').title()
        
        current_stats = current_bench.get('stats', {})
        current_mean = current_stats.get('mean', 0)
        current_ops = current_stats.get('ops', 0)
        
        base_bench = base_lookup.get(name)
        if base_bench:
            base_stats = base_bench.get('stats', {})
            base_mean = base_stats.get('mean', 0)
            base_ops = base_stats.get('ops', 0)
            
            change_percent, emoji = calculate_change_percentage(base_mean, current_mean)
            
            # Create visual change indicator
            if abs(change_percent) > 10:
                change_bar = "🔴🔴🔴" if change_percent > 0 else "🟢🟢🟢"
            elif abs(change_percent) > 5:
                change_bar = "🟡🟡" if change_percent > 0 else "🟢🟢"
            else:
                change_bar = "⚪"
            
            table += f"\n| **{test_name}** | `{format_time(base_mean)}` | `{format_time(current_mean)}` | **{change_percent:+.1f}%** {change_bar} | {emoji} |"
            
            # Track significant changes
            if abs(change_percent) > 5:
                direction = "🐌 slower" if change_percent > 0 else "🚀 faster"
                significant_changes.append(f"- **{test_name}**: {abs(change_percent):.1f}% {direction}")
                if change_percent > 0:
                    regressions += 1
                else:
                    improvements += 1
            else:
                no_change += 1
            
            # Add to performance summary
            ops_change = ((current_ops - base_ops) / base_ops) * 100 if base_ops > 0 else 0
            performance_summary.append({
                'name': test_name,
                'time_change': change_percent,
                'ops_change': ops_change,
                'current_ops': current_ops
            })
        else:
            table += f"\n| **{test_name}** | `-` | `{format_time(current_mean)}` | **New** 🆕 | 🆕 |"
            significant_changes.append(f"- **{test_name}**: New test 🆕")
    
    table += "\n\n</details>\n\n"
    
    # Add performance summary
    table += "## 🎯 Performance Summary\n\n"
    
    if improvements > 0 or regressions > 0:
        table += f"```diff\n"
        if improvements > 0:
            table += f"+ {improvements} performance improvement{'s' if improvements != 1 else ''} 🚀\n"
        if regressions > 0:
            table += f"- {regressions} performance regression{'s' if regressions != 1 else ''} ⚠️\n"
        if no_change > 0:
            table += f"  {no_change} test{'s' if no_change != 1 else ''} unchanged ✅\n"
        table += "```\n\n"
    else:
        table += "✅ **No significant performance changes detected** (all changes <5%)\n\n"
    
    # Add significant changes section
    if significant_changes:
        table += "### 🔍 Significant Changes (>5%)\n\n"
        for change in significant_changes:
            table += f"{change}\n"
        table += "\n"
    
    # Add top performers
    if performance_summary:
        fastest_test = max(performance_summary, key=lambda x: x['current_ops'])
        table += f"### ⚡ Fastest Operation\n"
        table += f"**{fastest_test['name']}** - {format_ops(fastest_test['current_ops'])}\n\n"
    
    return table


def generate_report(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate complete benchmark comparison report."""
    
    # Start building report with a nice header
    report = f"""# 🚀 Performance Benchmark Report

<div align="center">

**Branch Comparison:** `{base_branch}` → `{current_branch}`

![Performance](https://img.shields.io/badge/Performance-Benchmark-blue?style=for-the-badge&logo=github)
![Status](https://img.shields.io/badge/Status-Complete-green?style=for-the-badge)

</div>

---

"""
    
    if not current_data:
        report += """
> ⚠️ **No current benchmark data available**
> 
> This might be because:
> - Benchmarks failed to run
> - No benchmark tests found
> - Dependencies missing

"""
        return report
    
    if not base_data:
        report += f"""
> ℹ️ **No baseline benchmark data available**
> 
> Showing current results for `{current_branch}` only.

"""
        current_benchmarks = current_data.get('benchmarks', [])
        if current_benchmarks:
            report += generate_benchmark_table(current_benchmarks, f"📊 Current Results (`{current_branch}`)")
    else:
        # Add comparison
        comparison = generate_comparison_table(current_data, base_data, current_branch, base_branch)
        if comparison:
            report += comparison
    
    # Add environment info with nice formatting
    machine_info = current_data.get('machine_info', {})
    commit_info = current_data.get('commit_info', {})
    
    report += """---

<details>
<summary>🖥️ <strong>Test Environment</strong></summary>

"""
    
    report += f"- **🐍 Python**: `{machine_info.get('python_version', 'Unknown')}`\n"
    report += f"- **💻 Platform**: `{machine_info.get('platform', 'Unknown')}`\n"
    report += f"- **⚙️ CPU**: `{machine_info.get('processor', 'Unknown')}`\n"
    
    if commit_info:
        report += f"- **📝 Commit**: `{commit_info.get('id', 'Unknown')[:8]}`\n"
    
    report += "\n</details>\n\n"
    
    # Add footer
    report += """---"""
    
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