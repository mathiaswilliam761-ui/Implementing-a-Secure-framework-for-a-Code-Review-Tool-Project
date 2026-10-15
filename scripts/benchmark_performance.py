#!/usr/bin/env python3
"""
Performance Benchmark Script
Measures real wall-clock execution time and peak memory usage across scanners
under two configurations:
- Run A (Unoptimized Baseline): No exclusions, single-threaded, cold cache
- Run B (Optimized): With .semgrepignore, parallel jobs, git-diff targeting
"""

import subprocess
import time
import json
import os
import sys
import resource
from pathlib import Path
from typing import Dict, List, Any
import statistics

PROJECT_ROOT = Path("/opt/data/profiles/jack/home/secure-code-review-framework")
REPORTS_DIR = PROJECT_ROOT / "reports" / "tuned"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def get_memory_mb():
    """Get current memory usage in MB"""
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_maxrss / 1024  # Convert KB to MB on Linux

def run_command(cmd: List[str], cwd: str = None, env: Dict = None) -> Dict:
    """Run command and measure time + memory"""
    start_time = time.perf_counter()
    start_mem = get_memory_mb()
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd or PROJECT_ROOT),
            env={**os.environ, **(env or {})},
            capture_output=True,
            text=True,
            timeout=300
        )
        end_time = time.perf_counter()
        end_mem = get_memory_mb()
        
        duration = max(0.001, end_time - start_time)  # Avoid zero division
        return {
            "command": " ".join(cmd),
            "exit_code": result.returncode,
            "duration_seconds": round(duration, 3),
            "memory_mb": round(max(0, end_mem - start_mem), 2),
            "stdout": result.stdout[:1000] if result.stdout else "",
            "stderr": result.stderr[:1000] if result.stderr else "",
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        end_time = time.perf_counter()
        return {
            "command": " ".join(cmd),
            "exit_code": -1,
            "duration_seconds": round(max(0.001, end_time - start_time), 3),
            "memory_mb": 0,
            "stdout": "",
            "stderr": "TIMEOUT",
            "success": False
        }
    except Exception as e:
        end_time = time.perf_counter()
        return {
            "command": " ".join(cmd),
            "exit_code": -1,
            "duration_seconds": round(max(0.001, end_time - start_time), 3),
            "memory_mb": 0,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }

def count_files_scanned(scanner: str, target: str) -> int:
    """Count files that would be scanned"""
    if scanner == "semgrep":
        # Count code files
        result = subprocess.run(
            ["find", target, "-type", "f", "-name", "*.py", "-o", "-name", "*.js", "-o", "-name", "*.ts"],
            capture_output=True, text=True
        )
        return len([l for l in result.stdout.strip().split('\n') if l])
    return 0

def benchmark_semgrep(config_name: str, use_ignore: bool, parallel: bool, target: str = "vulnerable-samples/") -> Dict:
    """Benchmark Semgrep with given configuration"""
    cmd = ["semgrep", "scan", "--config", "scanners/semgrep-rules/custom-security-rules.yaml"]
    
    if not use_ignore:
        cmd.append("--ignore=.semgrepignore")  # Explicitly ignore the ignore file for baseline
    # If use_ignore=True, it will use .semgrepignore automatically
    
    if parallel:
        cmd.extend(["-j", str(os.cpu_count() or 4)])
    else:
        cmd.extend(["-j", "1"])
    
    cmd.extend(["--json", "--error", target])
    
    print(f"  Running Semgrep ({config_name})...")
    result = run_command(cmd)
    result["scanner"] = "semgrep"
    result["config"] = config_name
    result["target"] = target
    result["parallel"] = parallel
    result["use_ignore"] = use_ignore
    return result

def benchmark_bandit(config_name: str, target: str = "vulnerable-samples/python-app/") -> Dict:
    """Benchmark Bandit"""
    cmd = ["bandit", "-r", target, "-f", "json", "-q"]
    print(f"  Running Bandit ({config_name})...")
    result = run_command(cmd)
    result["scanner"] = "bandit"
    result["config"] = config_name
    result["target"] = target
    return result

def benchmark_eslint(config_name: str, target: str = "vulnerable-samples/node-app/server.js") -> Dict:
    """Benchmark ESLint"""
    cmd = ["npx", "eslint", target, "-f", "json", "--quiet"]
    print(f"  Running ESLint ({config_name})...")
    result = run_command(cmd, cwd=PROJECT_ROOT)
    result["scanner"] = "eslint"
    result["config"] = config_name
    result["target"] = target
    return result

def benchmark_gitleaks(config_name: str, target: str = "vulnerable-samples/") -> Dict:
    """Benchmark Gitleaks"""
    cmd = ["~/.local/bin/gitleaks", "detect", "--no-git", "--source", target, "--report-format", "json"]
    print(f"  Running Gitleaks ({config_name})...")
    result = run_command(cmd)
    result["scanner"] = "gitleaks"
    result["config"] = config_name
    result["target"] = target
    return result

def run_baseline_benchmarks() -> List[Dict]:
    """Run A: Unoptimized baseline (no exclusions, single-threaded)"""
    print("\n=== RUN A: Unoptimized Baseline ===")
    print("Configuration: No .semgrepignore, single-threaded (-j 1), cold cache")
    
    results = []
    
    # Clear any cache
    subprocess.run(["semgrep", "scan", "--clear-cache"], capture_output=True)
    
    # Semgrep without ignore, single-threaded
    results.append(benchmark_semgrep("baseline", use_ignore=False, parallel=False))
    
    # Bandit (always single-threaded)
    results.append(benchmark_bandit("baseline"))
    
    # ESLint
    results.append(benchmark_eslint("baseline"))
    
    # Gitleaks
    results.append(benchmark_gitleaks("baseline"))
    
    return results

def run_optimized_benchmarks() -> List[Dict]:
    """Run B: Optimized configuration (with ignore, parallel, diff-targeting)"""
    print("\n=== RUN B: Optimized Configuration ===")
    print("Configuration: .semgrepignore applied, parallel jobs, git-diff targeting")
    
    results = []
    
    # Semgrep with ignore, parallel
    results.append(benchmark_semgrep("optimized", use_ignore=True, parallel=True))
    
    # Bandit (same, but we can measure again)
    results.append(benchmark_bandit("optimized"))
    
    # ESLint (same)
    results.append(benchmark_eslint("optimized"))
    
    # Gitleaks (same)
    results.append(benchmark_gitleaks("optimized"))
    
    return results

def run_diff_targeted_benchmark() -> Dict:
    """Run Semgrep on git diff only (PR simulation)"""
    print("\n=== RUN C: Diff-Targeted (PR Simulation) ===")
    
    # Create a small diff by modifying one file
    test_file = PROJECT_ROOT / "vulnerable-samples" / "python-app" / "app.py"
    original = test_file.read_text()
    
    try:
        # Add a small change
        test_file.write_text(original + "\n# PR change\n")
        
        # Get diff
        result = subprocess.run(
            ["git", "diff", "HEAD"],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        
        # Run semgrep on changed files only
        cmd = [
            "semgrep", "scan",
            "--config", "scanners/semgrep-rules/custom-security-rules.yaml",
            "-j", str(os.cpu_count() or 4),
            "--json", "--error"
        ]
        
        # Get changed Python files
        changed = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        py_files = [f for f in changed.stdout.strip().split('\n') if f.endswith('.py')]
        if py_files:
            cmd.extend(py_files)
        
        result = run_command(cmd)
        result["scanner"] = "semgrep"
        result["config"] = "diff-targeted"
        result["target"] = "git diff"
        result["parallel"] = True
        result["use_ignore"] = True
        
    finally:
        # Restore
        test_file.write_text(original)
    
    return result

def main():
    print("=" * 60)
    print("SECURITY SCANNER PERFORMANCE BENCHMARK")
    print("=" * 60)
    print(f"Project: {PROJECT_ROOT}")
    print(f"CPU Cores: {os.cpu_count()}")
    
    all_results = []
    
    # Run A: Baseline
    baseline_results = run_baseline_benchmarks()
    all_results.extend(baseline_results)
    
    # Run B: Optimized
    optimized_results = run_optimized_benchmarks()
    all_results.extend(optimized_results)
    
    # Run C: Diff-targeted
    diff_result = run_diff_targeted_benchmark()
    all_results.append(diff_result)
    
    # Calculate speedups
    print("\n=== PERFORMANCE COMPARISON ===")
    
    comparison = {}
    for opt in optimized_results:
        scanner = opt["scanner"]
        base = next((r for r in baseline_results if r["scanner"] == scanner), None)
        if base and base["duration_seconds"] > 0:
            speedup = base["duration_seconds"] / opt["duration_seconds"]
            mem_savings = base["memory_mb"] - opt["memory_mb"]
            comparison[scanner] = {
                "baseline_seconds": base["duration_seconds"],
                "optimized_seconds": opt["duration_seconds"],
                "speedup_factor": round(speedup, 2),
                "time_saved_seconds": round(base["duration_seconds"] - opt["duration_seconds"], 2),
                "baseline_memory_mb": base["memory_mb"],
                "optimized_memory_mb": opt["memory_mb"],
                "memory_saved_mb": round(mem_savings, 2),
                "baseline_success": base["success"],
                "optimized_success": opt["success"]
            }
            print(f"\n  {scanner.upper()}:")
            print(f"    Baseline:  {base['duration_seconds']:.2f}s, {base['memory_mb']:.1f}MB")
            print(f"    Optimized: {opt['duration_seconds']:.2f}s, {opt['memory_mb']:.1f}MB")
            print(f"    Speedup:   {speedup:.2f}x faster")
            print(f"    Memory:    {mem_savings:.1f}MB saved")
    
    # Diff-targeted comparison
    base_semgrep = next((r for r in baseline_results if r["scanner"] == "semgrep"), None)
    if base_semgrep and diff_result["duration_seconds"] > 0:
        speedup = base_semgrep["duration_seconds"] / diff_result["duration_seconds"]
        comparison["semgrep-diff"] = {
            "baseline_seconds": base_semgrep["duration_seconds"],
            "optimized_seconds": diff_result["duration_seconds"],
            "speedup_factor": round(speedup, 2),
            "time_saved_seconds": round(base_semgrep["duration_seconds"] - diff_result["duration_seconds"], 2),
            "note": "Diff-targeted scan on changed files only"
        }
        print(f"\n  SEMGREP (diff-targeted):")
        print(f"    Baseline (full):  {base_semgrep['duration_seconds']:.2f}s")
        print(f"    Diff-targeted:    {diff_result['duration_seconds']:.2f}s")
        print(f"    Speedup:          {speedup:.2f}x faster")
    
    # Save results
    output = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "cpu_cores": os.cpu_count(),
            "project_root": str(PROJECT_ROOT),
            "python_version": sys.version.split()[0]
        },
        "baseline_runs": baseline_results,
        "optimized_runs": optimized_results,
        "diff_targeted_run": diff_result,
        "comparison": comparison
    }
    
    output_file = REPORTS_DIR / "benchmark_results.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n✅ Benchmark complete. Results saved to: {output_file}")
    
    # Print summary table
    print("\n" + "=" * 80)
    print("SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Scanner':<20} {'Baseline (s)':<15} {'Optimized (s)':<15} {'Speedup':<10} {'Mem Baseline':<15} {'Mem Optimized':<15} {'Mem Saved':<12}")
    print("-" * 80)
    
    for scanner, data in comparison.items():
        if isinstance(data, dict) and "speedup_factor" in data:
            # Handle cases where memory fields might be missing (e.g., diff-targeted)
            base_mem = data.get('baseline_memory_mb', 0)
            opt_mem = data.get('optimized_memory_mb', 0)
            mem_saved = data.get('memory_saved_mb', 0)
            print(f"{scanner:<20} {data['baseline_seconds']:<15.2f} {data['optimized_seconds']:<15.2f} "
                  f"{data['speedup_factor']:<10.2f}x {base_mem:<15.1f} "
                  f"{opt_mem:<15.1f} {mem_saved:<12.1f}")
    
    return output

if __name__ == "__main__":
    main()