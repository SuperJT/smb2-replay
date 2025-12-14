"""
Performance Monitoring Module.
Provides utilities to measure and track performance improvements in the SMB2 replay system.
"""

import functools
import gc
import json
import os
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

import pandas as pd
import psutil

from .config import get_logger

logger = get_logger()


class PerformanceMonitor:
    """Monitor and track performance metrics."""

    def __init__(self):
        self.metrics = {}
        self.benchmarks = []

    def measure_function(self, func_name: str | None = None):
        """Decorator to measure function performance.

        Args:
            func_name: Optional custom name for the function
        """

        def decorator(func):
            name = func_name or f"{func.__module__}.{func.__name__}"

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return self._measure_execution(name, func, *args, **kwargs)

            return wrapper

        return decorator

    def _measure_execution(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """Measure execution time and memory usage of a function."""
        logger.debug(f"Starting performance measurement for: {name}")

        # Pre-execution metrics
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024**2

        try:
            result = func(*args, **kwargs)

            # Post-execution metrics
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024**2

            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory

            # Store metrics
            self.metrics[name] = {
                "execution_time": execution_time,
                "memory_delta_mb": memory_delta,
                "start_memory_mb": start_memory,
                "end_memory_mb": end_memory,
                "timestamp": datetime.now().isoformat(),
                "success": True,
            }

            logger.info(
                f"Performance [{name}]: {execution_time:.3f}s, "
                f"Memory: {memory_delta:+.2f}MB ({start_memory:.2f} -> {end_memory:.2f})"
            )

            return result

        except Exception as e:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024**2

            self.metrics[name] = {
                "execution_time": end_time - start_time,
                "memory_delta_mb": end_memory - start_memory,
                "start_memory_mb": start_memory,
                "end_memory_mb": end_memory,
                "timestamp": datetime.now().isoformat(),
                "success": False,
                "error": str(e),
            }

            logger.error(f"Performance [{name}] failed: {e}")
            raise

    def benchmark_dataframe_operations(
        self, df: pd.DataFrame, sample_size: int = 1000
    ) -> dict[str, float]:
        """Benchmark common DataFrame operations.

        Args:
            df: DataFrame to benchmark
            sample_size: Size of sample for testing

        Returns:
            Dictionary with benchmark results
        """
        logger.info(f"Benchmarking DataFrame operations (sample size: {sample_size})")

        # Ensure we don't exceed DataFrame size
        sample_size = min(sample_size, len(df))
        sample_df = df.head(sample_size).copy()

        benchmarks = {}

        # Benchmark iterrows (slow method)
        start_time = time.time()
        count = 0
        for idx, row in sample_df.iterrows():
            count += 1
            if count >= 100:  # Limit to avoid long execution
                break
        benchmarks["iterrows_per_1000"] = (time.time() - start_time) * (1000 / count)

        # Benchmark vectorized operations (fast method)
        start_time = time.time()
        sample_df["test_column"] = sample_df.iloc[:, 0].apply(
            lambda x: str(x) if x else "N/A"
        )
        benchmarks["vectorized_apply"] = time.time() - start_time

        # Benchmark memory usage
        memory_mb = sample_df.memory_usage(deep=True).sum() / 1024**2
        benchmarks["memory_per_1000_rows"] = memory_mb * (1000 / len(sample_df))

        # Benchmark data type optimization
        start_time = time.time()
        optimized_df = self._optimize_test_dtypes(sample_df.copy())
        benchmarks["dtype_optimization"] = time.time() - start_time

        original_memory = sample_df.memory_usage(deep=True).sum() / 1024**2
        optimized_memory = optimized_df.memory_usage(deep=True).sum() / 1024**2
        benchmarks["memory_reduction_percent"] = (
            (original_memory - optimized_memory) / original_memory
        ) * 100

        logger.info(f"DataFrame benchmarks completed: {benchmarks}")
        return benchmarks

    def _optimize_test_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Test dtype optimization on a DataFrame."""
        # Convert numeric columns
        for col in df.select_dtypes(include=["int64", "float64"]).columns:
            if df[col].dtype == "int64":
                df[col] = pd.to_numeric(df[col], errors="coerce", downcast="integer")
            elif df[col].dtype == "float64":
                df[col] = pd.to_numeric(df[col], errors="coerce", downcast="float")

        # Convert string columns to category for repeated values with safe handling
        for col in df.select_dtypes(include=["object"]).columns:
            try:
                if df[col].nunique() / len(df) < 0.5:
                    # Handle existing categorical columns safely
                    if df[col].dtype.name == "category":
                        # Already categorical, skip
                        continue
                    else:
                        # Convert to categorical with error handling
                        df[col] = df[col].astype("category")
            except Exception as e:
                logger.debug(
                    f"Could not convert column {col} to categorical in performance monitor: {e}"
                )
                # Continue with other columns

        return df

    def memory_profile(self) -> dict[str, float]:
        """Get current memory profile.

        Returns:
            Dictionary with memory statistics
        """
        process = psutil.Process()
        memory_info = process.memory_info()
        virtual_memory = psutil.virtual_memory()

        profile = {
            "rss_mb": memory_info.rss / 1024**2,
            "vms_mb": memory_info.vms / 1024**2,
            "available_mb": virtual_memory.available / 1024**2,
            "percent_used": virtual_memory.percent,
            "cpu_percent": process.cpu_percent(),
        }

        logger.debug(f"Memory profile: {profile}")
        return profile

    def compare_implementations(
        self, old_func: Callable, new_func: Callable, *args, runs: int = 3, **kwargs
    ) -> dict[str, Any]:
        """Compare performance between old and new implementations.

        Args:
            old_func: Original function
            new_func: Optimized function
            *args: Function arguments
            runs: Number of test runs
            **kwargs: Function keyword arguments

        Returns:
            Comparison results
        """
        logger.info(
            f"Comparing implementations: {old_func.__name__} vs {new_func.__name__}"
        )

        old_times = []
        new_times = []
        old_memory = []
        new_memory = []

        for run in range(runs):
            logger.debug(f"Comparison run {run + 1}/{runs}")

            # Test old implementation
            gc.collect()
            start_memory = psutil.Process().memory_info().rss / 1024**2
            start_time = time.time()

            try:
                old_func(*args, **kwargs)
                old_success = True
            except Exception as e:
                logger.warning(f"Old implementation failed: {e}")
                old_success = False

            old_time = time.time() - start_time
            old_mem = psutil.Process().memory_info().rss / 1024**2 - start_memory

            old_times.append(old_time)
            old_memory.append(old_mem)

            # Test new implementation
            gc.collect()
            start_memory = psutil.Process().memory_info().rss / 1024**2
            start_time = time.time()

            try:
                new_func(*args, **kwargs)
                new_success = True
            except Exception as e:
                logger.warning(f"New implementation failed: {e}")
                new_success = False

            new_time = time.time() - start_time
            new_mem = psutil.Process().memory_info().rss / 1024**2 - start_memory

            new_times.append(new_time)
            new_memory.append(new_mem)

        # Calculate statistics
        avg_old_time = sum(old_times) / len(old_times)
        avg_new_time = sum(new_times) / len(new_times)
        avg_old_memory = sum(old_memory) / len(old_memory)
        avg_new_memory = sum(new_memory) / len(new_memory)

        time_improvement = ((avg_old_time - avg_new_time) / avg_old_time) * 100
        memory_improvement = (
            ((avg_old_memory - avg_new_memory) / avg_old_memory) * 100
            if avg_old_memory > 0
            else 0
        )

        comparison = {
            "old_function": old_func.__name__,
            "new_function": new_func.__name__,
            "runs": runs,
            "old_avg_time": avg_old_time,
            "new_avg_time": avg_new_time,
            "old_avg_memory_mb": avg_old_memory,
            "new_avg_memory_mb": avg_new_memory,
            "time_improvement_percent": time_improvement,
            "memory_improvement_percent": memory_improvement,
            "speedup_factor": (
                avg_old_time / avg_new_time if avg_new_time > 0 else float("inf")
            ),
            "old_success": old_success,
            "new_success": new_success,
        }

        logger.info(
            f"Comparison results: {time_improvement:.1f}% time improvement, "
            f"{memory_improvement:.1f}% memory improvement, "
            f"{comparison['speedup_factor']:.2f}x speedup"
        )

        return comparison

    def save_report(self, filepath: str):
        """Save performance report to file.

        Args:
            filepath: Path to save the report
        """
        report = {
            "metrics": self.metrics,
            "benchmarks": self.benchmarks,
            "system_info": {
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": psutil.virtual_memory().total / 1024**3,
                "timestamp": datetime.now().isoformat(),
            },
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Performance report saved to: {filepath}")

    def get_summary(self) -> dict[str, Any]:
        """Get performance summary.

        Returns:
            Summary of all metrics
        """
        if not self.metrics:
            return {"message": "No metrics recorded"}

        total_time = sum(m.get("execution_time", 0) for m in self.metrics.values())
        total_memory = sum(m.get("memory_delta_mb", 0) for m in self.metrics.values())
        successful_operations = sum(
            1 for m in self.metrics.values() if m.get("success", False)
        )

        return {
            "total_operations": len(self.metrics),
            "successful_operations": successful_operations,
            "total_execution_time": total_time,
            "total_memory_delta_mb": total_memory,
            "average_time_per_operation": total_time / len(self.metrics),
            "current_memory_profile": self.memory_profile(),
        }


# Global performance monitor instance
_performance_monitor: PerformanceMonitor | None = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def benchmark_optimizations(sample_data_path: str | None = None) -> dict[str, Any]:
    """Run comprehensive performance benchmarks.

    Args:
        sample_data_path: Optional path to sample data for testing

    Returns:
        Benchmark results
    """
    monitor = get_performance_monitor()
    logger.info("Starting comprehensive performance benchmarks")

    results = {
        "timestamp": datetime.now().isoformat(),
        "system_info": {
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": psutil.virtual_memory().total / 1024**3,
            "available_memory_gb": psutil.virtual_memory().available / 1024**3,
        },
    }

    # Create sample DataFrame for testing
    if sample_data_path and os.path.exists(sample_data_path):
        logger.info(f"Loading sample data from: {sample_data_path}")
        sample_df = pd.read_parquet(sample_data_path)
    else:
        logger.info("Creating synthetic sample data for benchmarking")
        sample_df = pd.DataFrame(
            {
                "frame.number": range(1000),
                "smb2.sesid": ["0x" + hex(i % 10)[2:].zfill(16) for i in range(1000)],
                "smb2.cmd": [str(i % 16) for i in range(1000)],
                "smb2.filename": [f"file_{i % 100}.txt" for i in range(1000)],
                "smb2.tid": ["0x" + hex(i % 5)[2:].zfill(8) for i in range(1000)],
                "ip.src": [f"192.168.1.{i % 255}" for i in range(1000)],
                "ip.dst": [f"10.0.0.{i % 255}" for i in range(1000)],
            }
        )

    # Benchmark DataFrame operations
    results["dataframe_benchmarks"] = monitor.benchmark_dataframe_operations(sample_df)

    # Memory profile
    results["memory_profile"] = monitor.memory_profile()

    # Summary
    results["summary"] = monitor.get_summary()

    logger.info("Performance benchmarks completed")
    return results
