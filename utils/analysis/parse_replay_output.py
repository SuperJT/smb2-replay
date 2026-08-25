#!/usr/bin/env python3
"""
Parse SMB2 replay output and present a summary.

Usage:
    python parse_replay_output.py < replay_output.txt
    docker logs container_name 2>&1 | python parse_replay_output.py
    python parse_replay_output.py --file replay_output.txt
"""

import argparse
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


def extract_replay_result(log_text: str) -> Optional[Dict[str, Any]]:
    """Extract the replay result JSON from log output."""
    # Look for the "Replay completed:" line with the dict
    pattern = r"Replay completed: (\{.*\})"
    match = re.search(pattern, log_text, re.DOTALL)
    if match:
        dict_str = match.group(1)
        try:
            # Try to parse as Python dict (uses single quotes)
            result = ast.literal_eval(dict_str)
            return result
        except (SyntaxError, ValueError):
            pass
        try:
            # Try to parse as JSON
            result = json.loads(dict_str)
            return result
        except json.JSONDecodeError:
            pass
    return None


def categorize_error(actual_status: str, actual_error: Optional[str]) -> str:
    """Categorize the error type based on status code."""
    status_map = {
        "0xc0000035": "NAME_COLLISION",
        "0xc0000043": "SHARING_VIOLATION",
        "0xc0000034": "OBJECT_NOT_FOUND",
        "0xc000003a": "OBJECT_PATH_NOT_FOUND",
        "0xc0000022": "ACCESS_DENIED",
        "0xc000006d": "LOGON_FAILURE",
    }
    return status_map.get(actual_status.lower(), actual_status)


def analyze_mismatches(
    details: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Group mismatches by error category."""
    mismatches_by_category: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for detail in details:
        if not detail.get("status_match", True):
            category = categorize_error(
                detail.get("actual_status", "unknown"),
                detail.get("actual_error"),
            )
            mismatches_by_category[category].append(detail)

    return dict(mismatches_by_category)


def extract_file_patterns(mismatches: List[Dict[str, Any]]) -> Counter:
    """Extract common file patterns from mismatches."""
    patterns: List[str] = []
    for m in mismatches:
        filename = m.get("filename", "")
        if filename and filename != "N/A":
            # Normalize path separators
            filename = filename.replace("\\\\", "\\")
            # Extract file extension or pattern
            if "." in filename:
                ext = filename.rsplit(".", 1)[-1]
                patterns.append(f"*.{ext}")
            else:
                patterns.append(filename.split("\\")[-1])
    return Counter(patterns)


def format_summary(result: Dict[str, Any]) -> str:
    """Format a readable summary of the replay result."""
    lines: List[str] = []

    # Header
    lines.append("=" * 70)
    lines.append("SMB2 REPLAY SUMMARY")
    lines.append("=" * 70)

    # Overall status
    success = result.get("success", False)
    status_icon = "✓" if success else "✗"
    lines.append(f"\nStatus: {status_icon} {'SUCCESS' if success else 'FAILED'}")

    # Operation counts
    total_ops = result.get("total_operations", 0)
    successful_ops = result.get("successful_operations", 0)
    failed_ops = result.get("failed_operations", 0)
    skipped_ops = total_ops - successful_ops - failed_ops

    lines.append(f"\n{'─' * 40}")
    lines.append("OPERATION SUMMARY")
    lines.append(f"{'─' * 40}")
    lines.append(f"  Total Operations:      {total_ops:,}")
    lines.append(f"  Successful:            {successful_ops:,}")
    lines.append(f"  Failed:                {failed_ops:,}")
    if skipped_ops > 0:
        lines.append(f"  Skipped:               {skipped_ops:,}")

    success_rate = (successful_ops / total_ops * 100) if total_ops > 0 else 0
    lines.append(f"  Success Rate:          {success_rate:.1f}%")

    # Mappings
    tid_mappings = result.get("tid_mappings", 0)
    fid_mappings = result.get("fid_mappings", 0)
    lines.append(f"\n  TID Mappings:          {tid_mappings}")
    lines.append(f"  FID Mappings:          {fid_mappings}")

    # Response validation
    rv = result.get("response_validation", {})
    if rv and rv.get("enabled"):
        lines.append(f"\n{'─' * 40}")
        lines.append("RESPONSE VALIDATION")
        lines.append(f"{'─' * 40}")

        rv_total = rv.get("total_operations", 0)
        rv_matching = rv.get("matching_responses", 0)
        rv_mismatched = rv.get("mismatched_responses", 0)
        match_rate = rv.get("match_rate", 0)

        lines.append(f"  Validated Operations:  {rv_total:,}")
        lines.append(f"  Matching Responses:    {rv_matching:,}")
        lines.append(f"  Mismatched Responses:  {rv_mismatched:,}")
        lines.append(f"  Match Rate:            {match_rate:.1f}%")

        # Analyze mismatches
        details = rv.get("details", [])
        if details:
            mismatches = analyze_mismatches(details)
            if mismatches:
                lines.append(f"\n{'─' * 40}")
                lines.append("MISMATCH BREAKDOWN BY ERROR TYPE")
                lines.append(f"{'─' * 40}")

                for category, items in sorted(
                    mismatches.items(), key=lambda x: -len(x[1])
                ):
                    lines.append(f"\n  {category}: {len(items)} occurrences")

                    # Get file patterns
                    patterns = extract_file_patterns(items)
                    if patterns:
                        lines.append("    File patterns:")
                        for pattern, count in patterns.most_common(5):
                            lines.append(f"      - {pattern}: {count}")

                    # Show first few examples
                    lines.append("    Examples:")
                    for item in items[:3]:
                        frame = item.get("frame", "?")
                        filename = item.get("filename", "N/A")
                        if len(filename) > 50:
                            filename = "..." + filename[-47:]
                        lines.append(f"      Frame {frame}: {filename}")

    # Issues
    issues = result.get("issues", [])
    if issues:
        lines.append(f"\n{'─' * 40}")
        lines.append("ISSUES")
        lines.append(f"{'─' * 40}")
        for issue in issues[:10]:
            lines.append(f"  • {issue}")
        if len(issues) > 10:
            lines.append(f"  ... and {len(issues) - 10} more")

    lines.append("\n" + "=" * 70)

    return "\n".join(lines)


def format_mismatch_table(
    details: List[Dict[str, Any]], limit: int = 50
) -> str:
    """Format mismatches as a table."""
    mismatches = [d for d in details if not d.get("status_match", True)]

    if not mismatches:
        return "No mismatches found."

    lines: List[str] = []
    lines.append(f"\n{'─' * 100}")
    lines.append(
        f"{'Frame':<8} {'Command':<20} {'Expected':<14} {'Actual':<14} {'Filename'}"
    )
    lines.append(f"{'─' * 100}")

    for m in mismatches[:limit]:
        frame = str(m.get("frame", "?"))
        command = m.get("command", "?")[:18]
        expected = m.get("expected_status", "?")
        actual = m.get("actual_status", "?")
        filename = m.get("filename", "N/A")

        # Truncate filename if too long
        max_fn_len = 45
        if len(filename) > max_fn_len:
            filename = "..." + filename[-(max_fn_len - 3) :]

        lines.append(f"{frame:<8} {command:<20} {expected:<14} {actual:<14} {filename}")

    if len(mismatches) > limit:
        lines.append(f"\n... and {len(mismatches) - limit} more mismatches")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse SMB2 replay output and display summary"
    )
    parser.add_argument(
        "--file", "-f", type=str, help="Input file (default: stdin)"
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Output as JSON"
    )
    parser.add_argument(
        "--table", "-t", action="store_true", help="Show mismatch table"
    )
    parser.add_argument(
        "--limit", "-l", type=int, default=50, help="Limit table rows"
    )
    args = parser.parse_args()

    # Read input
    if args.file:
        with open(args.file, "r") as f:
            log_text = f.read()
    else:
        log_text = sys.stdin.read()

    # Extract result
    result = extract_replay_result(log_text)

    if not result:
        print("ERROR: Could not find replay result in input", file=sys.stderr)
        sys.exit(1)

    if args.json:
        # Output as formatted JSON
        print(json.dumps(result, indent=2))
    else:
        # Output summary
        print(format_summary(result))

        # Optionally show mismatch table
        if args.table:
            details = result.get("response_validation", {}).get("details", [])
            print(format_mismatch_table(details, args.limit))


if __name__ == "__main__":
    main()
