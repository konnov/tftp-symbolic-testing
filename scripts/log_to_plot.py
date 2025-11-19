#!/usr/bin/env python3
"""
Analyze timing from python_harness.log files and produce stacked bar charts.

This script:
1. Reads all python_harness.log files in a directory
2. Collects time spent in JSON-RPC calls, TFTP operations, and Docker operations
3. Produces a stacked bar chart showing the time distribution

Note: Docker operations will only appear in logs from test runs that used the --docker flag.

Usage:
    python3 log_to_plot.py <logs_directory>
    python3 log_to_plot.py test-results
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError as e:
    print(f"Error: Required plotting libraries not installed: {e}", file=sys.stderr)
    print("Please install: pip install matplotlib numpy", file=sys.stderr)
    sys.exit(1)


class TimingAnalyzer:
    """Analyzes timing information from harness log files."""

    def __init__(self):
        # Categories of operations we track
        self.categories = {
            'json_rpc': 'JSON-RPC Client',
            'tftp_ops': 'TFTP Operations',
            'docker_ops': 'Docker Operations',
            'clock': 'Clock Advancement',
            'other': 'Other'
        }
        
        # Colors for each category
        self.colors = {
            'json_rpc': '#3498db',      # Blue
            'tftp_ops': '#2ecc71',      # Green
            'docker_ops': '#e74c3c',    # Red
            'clock': '#f39c12',         # Orange
            'other': '#95a5a6'          # Gray
        }

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line."""
        # Format: 2025-11-19 14:32:52,810
        match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
        if match:
            timestamp_str = match.group(1)
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
        return None

    def categorize_log_line(self, line: str) -> str:
        """Determine which category a log line belongs to."""
        # JSON-RPC client operations (from client.py logger and harness JSON-RPC calls)
        if ' - client - ' in line:
            return 'json_rpc'
        
        # Harness operations that invoke JSON-RPC
        if any(keyword in line for keyword in [
            'Trying transition',
            'Rollback to snapshot'
        ]):
            return 'json_rpc'
        
        # Docker operations (from docker_manager.py logger)
        if ' - docker_manager - ' in line:
            return 'docker_ops'
        
        # Clock advancement (time.sleep operations)
        if any(keyword in line for keyword in [
            'Advance Clock by',
            'Clock advanced by',
            'ActionAdvanceClock'
        ]):
            return 'clock'
        
        # TFTP operations (sending commands to docker clients, receiving SUT packets)
        if any(keyword in line for keyword in [
            'Sending RRQ command',
            'Sending ACK command',
            'Sending ERROR command',
            'TFTP operation for',
            'SUT PACKET:',
            'Received packet matches'
        ]):
            return 'tftp_ops'
        
        return 'other'

    def analyze_log_file(self, log_path: Path) -> Dict[str, float]:
        """
        Analyze a single log file and return time spent in each category.
        
        Returns:
            Dict mapping category name to time spent (in seconds)
        """
        times = defaultdict(float)
        
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {log_path}: {e}", file=sys.stderr)
            return times
        
        if not lines:
            return times
        
        # Track time between consecutive log entries
        prev_timestamp = None
        prev_category = None
        
        for line in lines:
            timestamp = self.parse_timestamp(line)
            if not timestamp:
                continue
            
            category = self.categorize_log_line(line)
            
            # Add time spent since previous log entry to previous category
            if prev_timestamp and prev_category:
                time_diff = (timestamp - prev_timestamp).total_seconds()
                # Cap at 10 seconds to avoid skewing results with long waits
                time_diff = min(time_diff, 10.0)
                times[prev_category] += time_diff
            
            prev_timestamp = timestamp
            prev_category = category
        
        return dict(times)

    def analyze_directory(self, directory: Path) -> Dict[str, Dict[str, float]]:
        """
        Analyze all python_harness.log files in a directory structure.
        
        Returns:
            Dict mapping run name to timing breakdown
        """
        results = {}
        
        # Find all python_harness.log files
        log_files = list(directory.glob('**/python_harness.log'))
        
        if not log_files:
            print(f"No python_harness.log files found in {directory}", file=sys.stderr)
            return results
        
        print(f"Found {len(log_files)} log files")
        
        for log_path in sorted(log_files):
            # Extract run name from path (e.g., run_0001)
            run_name = log_path.parent.name
            times = self.analyze_log_file(log_path)
            
            if times:
                results[run_name] = times
                total_time = sum(times.values())
                print(f"  {run_name}: {total_time:.2f}s total")
        
        return results

    def plot_stacked_bars(self, results: Dict[str, Dict[str, float]], output_path: Optional[str] = None):
        """
        Create a stacked bar chart showing time distribution.
        
        Args:
            results: Dict mapping run name to timing breakdown
            output_path: Optional path to save the figure
        """
        if not results:
            print("No data to plot", file=sys.stderr)
            return
        
        # Prepare data for plotting
        run_names = sorted(results.keys())
        
        # Build data matrix
        category_keys = ['json_rpc', 'tftp_ops', 'docker_ops', 'clock', 'other']
        data = {cat: [] for cat in category_keys}
        
        for run_name in run_names:
            times = results[run_name]
            for cat in category_keys:
                data[cat].append(times.get(cat, 0.0))
        
        # Create the plot
        fig, ax = plt.subplots(figsize=(max(12, len(run_names) * 0.3), 6))
        
        # X positions for bars
        x = np.arange(len(run_names))
        width = 0.8
        
        # Plot stacked bars
        bottom = np.zeros(len(run_names))
        
        for cat in category_keys:
            values = data[cat]
            ax.bar(x, values, width, label=self.categories[cat], 
                   bottom=bottom, color=self.colors[cat])
            bottom += values
        
        # Customize the plot
        ax.set_xlabel('Test Run', fontsize=12, fontweight='bold')
        ax.set_ylabel('Time (seconds)', fontsize=12, fontweight='bold')
        ax.set_title('Time Distribution Across Test Runs', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        
        # Set x-axis labels
        if len(run_names) > 20:
            # Show every Nth label to avoid crowding
            step = max(1, len(run_names) // 20)
            labels = [run_names[i] if i % step == 0 else '' for i in range(len(run_names))]
            ax.set_xticklabels(labels, rotation=45, ha='right')
        else:
            ax.set_xticklabels(run_names, rotation=45, ha='right')
        
        ax.legend(loc='upper left', fontsize=10)
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        
        # Save or show
        if output_path:
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            print(f"\nPlot saved to {output_path}")
        else:
            plt.show()

    def print_summary(self, results: Dict[str, Dict[str, float]]):
        """Print summary statistics."""
        if not results:
            return
        
        print("\n" + "="*80)
        print("SUMMARY STATISTICS")
        print("="*80)
        
        # Aggregate across all runs
        totals = defaultdict(float)
        for times in results.values():
            for cat, time in times.items():
                totals[cat] += time
        
        total_time = sum(totals.values())
        
        print(f"\nTotal time across {len(results)} runs: {total_time:.2f}s")
        print(f"Average time per run: {total_time/len(results):.2f}s\n")
        
        print("Time by category:")
        for cat in ['json_rpc', 'tftp_ops', 'docker_ops', 'clock', 'other']:
            if cat in totals:
                time = totals[cat]
                percentage = (time / total_time * 100) if total_time > 0 else 0
                print(f"  {self.categories[cat]:25s}: {time:8.2f}s ({percentage:5.1f}%)")
        
        print("="*80)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze timing from TFTP harness logs and produce stacked bar charts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s test-results
  %(prog)s test-results --output timing_plot.png
        """
    )
    parser.add_argument(
        'directory',
        type=str,
        help='Directory containing test results (with python_harness.log files)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output file path for the plot (default: show interactive plot)'
    )
    
    args = parser.parse_args()
    
    # Validate directory
    directory = Path(args.directory)
    if not directory.exists():
        print(f"Error: Directory '{directory}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    if not directory.is_dir():
        print(f"Error: '{directory}' is not a directory", file=sys.stderr)
        sys.exit(1)
    
    # Analyze logs
    analyzer = TimingAnalyzer()
    results = analyzer.analyze_directory(directory)
    
    if not results:
        print("No timing data found", file=sys.stderr)
        sys.exit(1)
    
    # Print summary
    analyzer.print_summary(results)
    
    # Create plot
    analyzer.plot_stacked_bars(results, args.output)


if __name__ == '__main__':
    main()
