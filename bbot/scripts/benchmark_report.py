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
import time
import re
import ast
from pathlib import Path
from typing import Dict, List, Any, Tuple


def run_command(cmd: List[str], cwd: Path = None, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=capture_output, text=True, check=True)
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
            "poetry",
            "run",
            "python",
            "-m",
            "pytest",
            "bbot/test/benchmarks/",
            "--benchmark-only",
            f"--benchmark-json={output_file}",
            "-q",
        ]
        run_command(cmd, cwd=repo_path, capture_output=False)
        return True
    except subprocess.CalledProcessError:
        print("Benchmarks failed for current state")
        return False


def resolve_expression(node, variables, file_path):
    """Recursively resolve an AST expression to a string value."""
    try:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value, None
        elif isinstance(node, ast.Name) and node.id in variables:
            return variables[node.id], None
        elif isinstance(node, ast.JoinedStr):  # f-string
            try:
                # Check if f-string contains unresolved variables
                f_string_content = ast.unparse(node)
                if any(
                    char.isalpha() and char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
                    for char in f_string_content
                ):
                    return None, f"F-string with unresolved variables: {f_string_content}"
                return f_string_content, None
            except (ValueError, TypeError):
                return None, "Complex f-string that cannot be resolved"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # String concatenation
            left, left_reason = resolve_expression(node.left, variables, file_path)
            right, right_reason = resolve_expression(node.right, variables, file_path)
            if left is not None and right is not None:
                return str(left) + str(right), None
            elif left_reason:
                return None, f"Left operand: {left_reason}"
            elif right_reason:
                return None, f"Right operand: {right_reason}"
            else:
                return None, "String concatenation with unresolved parts"
        elif isinstance(node, ast.Call):
            # Handle re.escape() calls
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr == "escape"
            ):
                if node.args:
                    arg_value, reason = resolve_expression(node.args[0], variables, file_path)
                    if arg_value:
                        return re.escape(arg_value), None
                    else:
                        return None, f"re.escape() argument: {reason}"
            # Handle ''.join() calls
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Constant)
                and node.func.value.value == ""
                and node.func.attr == "join"
            ):
                if node.args:
                    arg_value, reason = resolve_expression(node.args[0], variables, file_path)
                    if isinstance(arg_value, list):
                        return "".join(arg_value), None
                    else:
                        return None, f"join() argument: {reason}"
            # Handle other function calls - try to resolve arguments
            elif node.args:
                resolved_args = []
                unresolved_reasons = []
                for arg in node.args:
                    arg_value, reason = resolve_expression(arg, variables, file_path)
                    if arg_value is not None:
                        resolved_args.append(str(arg_value))
                    elif reason:
                        unresolved_reasons.append(reason)
                if resolved_args and not unresolved_reasons:
                    return "".join(resolved_args), None
                else:
                    return None, f"Function call with unresolved arguments: {', '.join(unresolved_reasons)}"
            else:
                return None, "Function call without arguments"
        elif isinstance(node, ast.ListComp):
            # Handle list comprehensions like [char for char in blacklist_chars]
            return None, f"List comprehension: {ast.unparse(node)}"
        elif isinstance(node, ast.List):
            # Handle list literals
            resolved_elements = []
            unresolved_reasons = []
            for elt in node.elts:
                elt_value, reason = resolve_expression(elt, variables, file_path)
                if elt_value is not None:
                    resolved_elements.append(str(elt_value))
                elif reason:
                    unresolved_reasons.append(reason)
            if resolved_elements and not unresolved_reasons:
                return resolved_elements, None
            else:
                return None, f"List with unresolved elements: {', '.join(unresolved_reasons)}"
        elif isinstance(node, ast.Attribute):
            # Handle attribute access like self.dns_strings
            return None, f"Attribute access: {ast.unparse(node)}"
        elif isinstance(node, ast.Subscript):
            # Handle subscript access like list[index]
            return None, f"Subscript access: {ast.unparse(node)}"
    except Exception as e:
        return None, f"Exception during resolution: {str(e)}"
    return None, "Unknown expression type"


def find_regexes_in_codebase() -> List[Dict[str, Any]]:
    """Find all regex patterns in the BBOT codebase"""
    import ast
    import os

    regexes_found = []
    bbot_dir = Path(__file__).parent.parent

    for root, dirs, files in os.walk(bbot_dir):
        # Skip certain directories
        if any(
            skip in root
            for skip in ["__pycache__", ".git", "node_modules", ".pytest_cache", "test", "tests", "scripts"]
        ):
            continue

        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Parse AST to find regex patterns
                    tree = ast.parse(content)

                    # Track variables that might contain regex patterns
                    variables = {}

                    # First pass: collect variable assignments
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Assign):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    value, reason = resolve_expression(node.value, variables, file_path)
                                    if value is not None:
                                        variables[target.id] = value

                    # Second pass: find regex usage
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if (
                                isinstance(node.func, ast.Attribute)
                                and isinstance(node.func.value, ast.Name)
                                and node.func.value.id == "re"
                                and node.func.attr == "compile"
                            ):
                                pattern = None
                                reason = None

                                # Get the regex pattern argument
                                if node.args:
                                    arg = node.args[0]
                                    pattern, reason = resolve_expression(arg, variables, file_path)

                                # Get line number
                                line_no = node.lineno

                                # Get relative path
                                rel_path = file_path.relative_to(bbot_dir)

                                if pattern and isinstance(pattern, str):
                                    # Clean up the pattern (remove quotes, etc.)
                                    pattern = pattern.strip("\"'")

                                    # Skip if pattern is too short or likely not a real regex
                                    if len(pattern) < 2 or pattern.startswith("#"):
                                        continue

                                    regexes_found.append(
                                        {
                                            "file": str(rel_path),
                                            "line": line_no,
                                            "pattern": pattern,
                                            "function": node.func.attr,
                                            "full_path": str(file_path),
                                            "status": "testable",
                                        }
                                    )
                                elif reason:
                                    # Add to untestable patterns
                                    regexes_found.append(
                                        {
                                            "file": str(rel_path),
                                            "line": line_no,
                                            "pattern": ast.unparse(node.args[0]) if node.args else "Unknown",
                                            "function": node.func.attr,
                                            "full_path": str(file_path),
                                            "status": "untestable",
                                            "reason": reason,
                                        }
                                    )

                except (SyntaxError, UnicodeDecodeError):
                    continue

    return regexes_found


def analyze_regex_performance() -> Dict[str, Any]:
    """Analyze regex performance and return benchmark data"""

    # Find actual regexes in the codebase
    print("🔍 Scanning BBOT codebase for regex patterns...")
    regexes_found = find_regexes_in_codebase()

    if not regexes_found:
        print("Warning: No regex patterns found in codebase")
        return {"benchmarks": [], "regex_summary": {}}

    print(f"Found {len(regexes_found)} regex patterns")

    # Test data of different sizes
    test_strings = {
        "short": ["a", "test", "example.com"],
        "medium": ["user@domain.com", "192.168.1.1", "https://example.com"],
        "long": ["a" * 100, "b" * 100, "c" * 100],
        "very_long": ["a" * 1000, "b" * 1000, "c" * 1000],
    }

    # Separate testable and untestable patterns
    testable_patterns = []
    untestable_patterns = []

    for regex_info in regexes_found:
        if regex_info.get("status") == "testable":
            testable_patterns.append(
                (
                    f"{regex_info['file']}:{regex_info['line']}",
                    regex_info["pattern"],
                    regex_info["file"],
                    regex_info["line"],
                )
            )
        else:
            untestable_patterns.append(regex_info)

    print(f"Found {len(testable_patterns)} testable patterns and {len(untestable_patterns)} untestable patterns")

    # Use only testable patterns for performance testing
    patterns = testable_patterns

    results = []
    benchmarks = []

    for name, pattern, file_path, line_no in patterns:
        try:
            # Compilation timing
            start = time.perf_counter()
            compiled = re.compile(pattern)
            compile_time = (time.perf_counter() - start) * 1000

            # Performance across different input sizes
            size_results = {}
            total_matches = 0

            for size, strings in test_strings.items():
                times = []
                matches = 0

                for test_string in strings:
                    # Time the match
                    start = time.perf_counter()
                    match = compiled.search(test_string)
                    end = time.perf_counter()

                    match_time = (end - start) * 1000
                    times.append(match_time)

                    if match:
                        matches += 1

                    total_matches += 1 if match else 0

                avg_time = sum(times) / len(times)
                max_time = max(times)

                size_results[size] = {
                    "avg_time": avg_time,
                    "max_time": max_time,
                    "matches": matches,
                    "total_tests": len(strings),
                }

                # Create benchmark entry
                match_stats = {
                    "mean": avg_time / 1000,  # Convert to seconds
                    "min": avg_time / 1000,
                    "max": max_time / 1000,
                    "ops": 1 / (avg_time / 1000) if avg_time > 0 else 0,
                }

                benchmarks.append(
                    {
                        "name": f"test_regex_{name}_matching_{size}",
                        "stats": match_stats,
                        "extra_info": {
                            "pattern": pattern[:100] + "..." if len(pattern) > 100 else pattern,
                            "type": "matching",
                            "input_size": size,
                            "matches": matches,
                            "total_tests": len(strings),
                            "file": file_path,
                            "line": line_no,
                        },
                    }
                )

            # Compilation benchmark
            compile_stats = {
                "mean": compile_time / 1000,  # Convert to seconds
                "min": compile_time / 1000,
                "max": compile_time / 1000,
                "ops": 1 / (compile_time / 1000) if compile_time > 0 else 0,
            }

            benchmarks.append(
                {
                    "name": f"test_regex_{name}_compilation",
                    "stats": compile_stats,
                    "extra_info": {
                        "pattern": pattern[:100] + "..." if len(pattern) > 100 else pattern,
                        "type": "compilation",
                        "file": file_path,
                        "line": line_no,
                    },
                }
            )

            # Store results
            results.append(
                {
                    "name": name,
                    "pattern": pattern,
                    "file": file_path,
                    "line": line_no,
                    "compile_time": compile_time,
                    "size_results": size_results,
                    "total_matches": total_matches,
                    "status": "success",
                }
            )

        except re.error as e:
            results.append(
                {
                    "name": name,
                    "pattern": pattern,
                    "file": file_path,
                    "line": line_no,
                    "status": "error",
                    "error": str(e),
                }
            )

    # Generate summary statistics
    successful_results = [r for r in results if r["status"] == "success"]
    summary = {
        "patterns_tested": len(successful_results),
        "patterns_untestable": len(untestable_patterns),
        "total_benchmarks": len(benchmarks),
        "compilation_times": [r["compile_time"] for r in successful_results],
        "matching_times": [],
        "slow_patterns": [],
        "problematic_patterns": [],
        "detailed_results": results,
        "untestable_patterns": untestable_patterns,
    }

    # Collect matching times and identify slow patterns
    for r in successful_results:
        for size, data in r["size_results"].items():
            summary["matching_times"].append(data["avg_time"])
            if data["max_time"] > 1.0:  # 1ms threshold
                summary["slow_patterns"].append(
                    {
                        "name": r["name"],
                        "file": r["file"],
                        "line": r["line"],
                        "pattern": r["pattern"],
                        "size": size,
                        "max_time": data["max_time"],
                    }
                )

    # Identify problematic patterns (compilation errors, very slow, etc.)
    for r in results:
        if r["status"] == "error":
            summary["problematic_patterns"].append(
                {
                    "type": "compilation_error",
                    "file": r["file"],
                    "line": r["line"],
                    "pattern": r["pattern"],
                    "error": r["error"],
                }
            )
        elif r["status"] == "success":
            # Check for very slow compilation
            if r["compile_time"] > 10.0:  # 10ms threshold
                summary["problematic_patterns"].append(
                    {
                        "type": "slow_compilation",
                        "file": r["file"],
                        "line": r["line"],
                        "pattern": r["pattern"],
                        "compile_time": r["compile_time"],
                    }
                )

    return {"benchmarks": benchmarks, "regex_summary": summary}


def load_benchmark_data(filepath: Path) -> Dict[str, Any]:
    """Load benchmark data from JSON file."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Benchmark file not found: {filepath}")
        return {}
    except json.JSONDecodeError:
        print(f"Warning: Could not parse JSON from {filepath}")
        return {}


def format_time(seconds: float) -> str:
    """Format time in human-readable format."""
    if seconds < 0.000001:  # Less than 1 microsecond
        return f"{seconds * 1000000000:.0f}ns"  # Show as nanoseconds with no decimal
    elif seconds < 0.001:  # Less than 1 millisecond
        return f"{seconds * 1000000:.2f}µs"  # Show as microseconds with 2 decimal places
    elif seconds < 1:  # Less than 1 second
        return f"{seconds * 1000:.2f}ms"  # Show as milliseconds with 2 decimal places
    else:
        return f"{seconds:.3f}s"  # Show as seconds with 3 decimal places


def format_ops(ops: float) -> str:
    """Format operations per second."""
    if ops > 1000:
        return f"{ops / 1000:.1f}K ops/sec"
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
        stats = bench.get("stats", {})
        name = bench.get("name", "Unknown")
        # Generic test name cleanup - just remove 'test_' prefix and format nicely
        test_name = name.replace("test_", "").replace("_", " ").title()

        mean = format_time(stats.get("mean", 0))
        ops = format_ops(stats.get("ops", 0))
        min_time = format_time(stats.get("min", 0))
        max_time = format_time(stats.get("max", 0))

        table += f"| {test_name} | {mean} | {ops} | {min_time} | {max_time} |\n"

    return table + "\n"


def generate_comparison_table(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate comparison table between current and base benchmark results."""
    if not current_data or not base_data:
        return ""

    current_benchmarks = current_data.get("benchmarks", [])
    base_benchmarks = base_data.get("benchmarks", [])

    # Create lookup for base benchmarks
    base_lookup = {bench["name"]: bench for bench in base_benchmarks}

    if not current_benchmarks:
        return ""

    # Count changes for summary
    improvements = 0
    regressions = 0
    no_change = 0

    table = f"""## 📊 Performance Benchmark Results

> Comparing **`{base_branch}`** (baseline) vs **`{current_branch}`** (current)

<details>
<summary>📈 <strong>Detailed Results</strong> (All Benchmarks)</summary>

> 📋 **Complete results for all benchmarks** - includes both significant and insignificant changes

| 🧪 Test Name | 📏 Base | 📏 Current | 📈 Change | 🎯 Status |
|--------------|---------|------------|-----------|-----------|"""

    significant_changes = []
    performance_summary = []

    for current_bench in current_benchmarks:
        name = current_bench.get("name", "Unknown")
        # Generic test name cleanup - just remove 'test_' prefix and format nicely
        test_name = name.replace("test_", "").replace("_", " ").title()

        current_stats = current_bench.get("stats", {})
        current_mean = current_stats.get("mean", 0)
        current_ops = current_stats.get("ops", 0)

        base_bench = base_lookup.get(name)
        if base_bench:
            base_stats = base_bench.get("stats", {})
            base_mean = base_stats.get("mean", 0)
            base_ops = base_stats.get("ops", 0)

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
            performance_summary.append(
                {
                    "name": test_name,
                    "time_change": change_percent,
                    "ops_change": ops_change,
                    "current_ops": current_ops,
                }
            )
        else:
            table += f"\n| **{test_name}** | `-` | `{format_time(current_mean)}` | **New** 🆕 | 🆕 |"
            significant_changes.append(f"- **{test_name}**: New test 🆕")

    table += "\n\n</details>\n\n"

    # Add performance summary
    table += "## 🎯 Performance Summary\n\n"

    if improvements > 0 or regressions > 0:
        table += "```diff\n"
        if improvements > 0:
            table += f"+ {improvements} improvement{'s' if improvements != 1 else ''} 🚀\n"
        if regressions > 0:
            table += f"! {regressions} regression{'s' if regressions != 1 else ''} ⚠️\n"
        if no_change > 0:
            table += f"  {no_change} unchanged ✅\n"
        table += "```\n\n"
    else:
        table += "✅ **No significant performance changes detected** (all changes <5%)\n\n"

    # Add significant changes section
    if significant_changes:
        table += "### 🔍 Significant Changes (>5%)\n\n"
        for change in significant_changes:
            table += f"{change}\n"
        table += "\n"

    return table


def generate_report(current_data: Dict, base_data: Dict, current_branch: str, base_branch: str) -> str:
    """Generate complete benchmark comparison report."""

    if not current_data:
        report = """## 🚀 Performance Benchmark Report

> ⚠️ **No current benchmark data available**
> 
> This might be because:
> - Benchmarks failed to run
> - No benchmark tests found
> - Dependencies missing

"""
        return report

    if not base_data:
        report = f"""## 🚀 Performance Benchmark Report

> ℹ️ **No baseline benchmark data available**
> 
> Showing current results for **{current_branch}** only.

"""
        current_benchmarks = current_data.get("benchmarks", [])
        if current_benchmarks:
            report += f"""<details>
<summary>📊 Current Results (`{current_branch}`) - Click to expand</summary>

{generate_benchmark_table(current_benchmarks, "Results")}
</details>"""
    else:
        # Add comparison
        comparison = generate_comparison_table(current_data, base_data, current_branch, base_branch)
        if comparison:
            report = comparison
        else:
            # Fallback if no comparison data
            report = f"""## 🚀 Performance Benchmark Report

> ℹ️ **No baseline benchmark data available**
> 
> Showing current results for **{current_branch}** only.

"""

    # Add regex analysis section if available
    machine_info = current_data.get("machine_info", {})
    python_version = machine_info.get("python_version", "Unknown")
    regex_analysis = machine_info.get("regex_analysis", {})

    if regex_analysis:
        report += "\n\n## 🔍 Regex Performance Analysis\n\n"
        report += f"**Patterns Tested**: {regex_analysis.get('patterns_tested', 0)}\n"
        report += f"**Patterns Untestable**: {regex_analysis.get('patterns_untestable', 0)}\n\n"

        # Error patterns
        if regex_analysis.get("problematic_patterns") or regex_analysis.get("slow_patterns"):
            report += "<details>\n<summary>⚠️ <strong>Issues Found</strong></summary>\n\n"

            if regex_analysis.get("problematic_patterns"):
                report += "### ❌ Problematic Patterns\n\n"
                for problem in regex_analysis["problematic_patterns"]:
                    if problem["type"] == "compilation_error":
                        report += f"**❌ Compilation Error**: `{problem['file']}:{problem['line']}`\n"
                        report += f"   Error: {problem['error']}\n"
                        report += f"   Pattern: `{problem['pattern'][:100]}{'...' if len(problem['pattern']) > 100 else ''}`\n\n"
                    elif problem["type"] == "slow_compilation":
                        report += f"**🐌 Slow Compilation**: `{problem['file']}:{problem['line']}`\n"
                        report += f"   Time: {problem['compile_time']:.3f}ms\n"
                        report += f"   Pattern: `{problem['pattern'][:100]}{'...' if len(problem['pattern']) > 100 else ''}`\n\n"

            if regex_analysis.get("slow_patterns"):
                report += "### 🐌 Slow Matching Patterns\n\n"
                for pattern in regex_analysis["slow_patterns"]:
                    report += f"**File**: `{pattern['file']}:{pattern['line']}`\n"
                    report += f"**Time**: {pattern['max_time']:.3f}ms ({pattern['size']} input)\n"
                    report += f"**Pattern**: `{pattern['pattern'][:100]}{'...' if len(pattern['pattern']) > 100 else ''}`\n\n"

            report += "</details>\n\n"

        # All patterns list (collapsible)
        if regex_analysis.get("detailed_results"):
            report += "<details>\n<summary>📋 <strong>All Regex Patterns</strong></summary>\n\n"
            report += "| File:Line | Pattern | Compile (ms) | Max Match (ms) | Status |\n"
            report += "|-----------|---------|--------------|----------------|--------|\n"

            # Sort by max matching time (slowest first) for highlighting
            sorted_results = sorted(
                regex_analysis["detailed_results"],
                key=lambda x: max([data["max_time"] for data in x["size_results"].values()])
                if x["status"] == "success"
                else 0,
                reverse=True,
            )

            # Get the 10 slowest patterns
            slowest_10 = set()
            for i, result in enumerate(sorted_results[:10]):
                if result["status"] == "success":
                    slowest_10.add(f"{result['file']}:{result['line']}")

            # Get problematic patterns
            problematic_patterns = set()
            for problem in regex_analysis.get("problematic_patterns", []):
                problematic_patterns.add(f"{problem['file']}:{problem['line']}")

            for result in sorted_results:
                file_line = f"`{result['file']}:{result['line']}`"
                # Escape pipe characters and other markdown table breaking characters
                raw_pattern = result["pattern"]
                escaped_pattern = raw_pattern.replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")
                pattern = escaped_pattern[:60] + "..." if len(escaped_pattern) > 60 else escaped_pattern

                # Highlight slowest 10 and problematic patterns
                highlight = ""
                if f"{result['file']}:{result['line']}" in slowest_10:
                    highlight = "**🟡 SLOW** "
                if f"{result['file']}:{result['line']}" in problematic_patterns:
                    highlight = "**🔴 ERROR** "

                if result["status"] == "success":
                    compile_time = f"{result['compile_time']:.3f}"
                    max_match_time = max([data["max_time"] for data in result["size_results"].values()])
                    max_match_str = f"{max_match_time:.3f}"

                    # Add warning indicators
                    status = "✅"
                    if max_match_time > 1.0:
                        status = "⚠️"
                    if result["compile_time"] > 10.0:
                        status = "⚡"

                    report += (
                        f"| {highlight}{file_line} | `{pattern}` | {compile_time} | {max_match_str} | {status} |\n"
                    )
                else:
                    report += f"| {highlight}{file_line} | `{pattern}` | ❌ Error | ❌ Error | ❌ |\n"

            report += "\n</details>\n\n"

        # Untestable patterns section
        if regex_analysis.get("untestable_patterns"):
            report += "<details>\n<summary>❌ <strong>Untestable Patterns</strong></summary>\n\n"
            report += "| File:Line | Pattern | Reason |\n"
            report += "|-----------|---------|--------|\n"

            for pattern_info in regex_analysis["untestable_patterns"]:
                file_line = f"`{pattern_info['file']}:{pattern_info['line']}`"
                pattern = (
                    pattern_info["pattern"][:60] + "..."
                    if len(pattern_info["pattern"]) > 60
                    else pattern_info["pattern"]
                )
                reason = pattern_info.get("reason", "Unknown")

                # Escape pipe characters in pattern and reason
                pattern = pattern.replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")
                reason = reason.replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")

                report += f"| {file_line} | `{pattern}` | {reason} |\n"

            report += "\n</details>\n\n"

    report += f"\n\n---\n\n🐍 Python Version {python_version}"

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
        
        # Initialize data structures with machine_info for regex analysis
        base_data["machine_info"] = {}
        current_data["machine_info"] = {}

        try:
            # Run benchmarks on base branch
            print(f"\n=== Running benchmarks on base branch: {args.base} ===")
            checkout_branch(args.base, repo_path)
            if run_benchmarks(base_results_file, repo_path):
                base_data = load_benchmark_data(base_results_file)
            
            # Add regex analysis to base branch data (but don't mix with benchmarks)
            print("🔍 Adding regex performance analysis to base branch...")
            base_regex_data = analyze_regex_performance()
            
            # Add regex summary only (no benchmarks)
            if "machine_info" not in base_data:
                base_data["machine_info"] = {}
            base_data["machine_info"]["regex_analysis"] = base_regex_data["regex_summary"]

            # Run benchmarks on current branch
            print(f"\n=== Running benchmarks on current branch: {args.current} ===")
            checkout_branch(args.current, repo_path)
            if run_benchmarks(current_results_file, repo_path):
                current_data = load_benchmark_data(current_results_file)
            
            # Add regex analysis to current branch data (but don't mix with benchmarks)
            print("🔍 Adding regex performance analysis to current branch...")
            current_regex_data = analyze_regex_performance()
            print(f"Debug: current_regex_data keys: {list(current_regex_data.keys())}")
            print(f"Debug: regex_summary keys: {list(current_regex_data.get('regex_summary', {}).keys())}")
            
            # Add regex summary only (no benchmarks)
            if "machine_info" not in current_data:
                current_data["machine_info"] = {}
            current_data["machine_info"]["regex_analysis"] = current_regex_data["regex_summary"]
            print(f"Debug: current_data structure: {current_data}")

            # Generate report
            print("\n=== Generating comparison report ===")
            report = generate_report(current_data, base_data, args.current, args.base)

            # Output report
            if args.output:
                with open(args.output, "w") as f:
                    f.write(report)
                print(f"Report written to {args.output}")
            else:
                print("\n" + "=" * 80)
                print(report)

            # Keep results if requested
            if args.keep_results:
                if base_data:
                    with open("base_benchmark_results.json", "w") as f:
                        json.dump(base_data, f, indent=2)
                if current_data:
                    with open("current_benchmark_results.json", "w") as f:
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
