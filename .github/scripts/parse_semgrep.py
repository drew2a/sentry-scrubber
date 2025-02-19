#!/usr/bin/env python3
"""
Parse Semgrep JSON output and create GitHub Actions annotations.

This script reads Semgrep analysis results from a JSON file and converts them
into GitHub Actions warning annotations. For each issue found by Semgrep,
it creates an annotation containing the file path, line number, message,
suggested fix (if available), and references (if available).

The Semgrep JSON output is expected to have a 'results' array containing objects with:
- path: file path where the issue was found
- start: object containing 'line' number
- extra: object containing 'message' description
- fix: optional fix suggestion
- extra.metadata.references: optional list of reference URLs

Usage:
    python parse_semgrep.py [input_file] [--fail-on SEVERITY,...]

Arguments:
    input_file          JSON file containing Semgrep results (default: results.json)
    --fail-on          Comma-separated list of severity levels that will cause script
                       to exit with error (e.g., --fail-on ERROR,WARNING)

The script processes all results before exiting, ensuring all issues are reported.
Exit code 1 indicates that issues with specified severity levels were found.
"""
import json
import sys
from pathlib import Path


def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', nargs='?', default='results.json',
                        help='JSON file containing Semgrep results')
    parser.add_argument('--fail-on', type=str,
                        help='Comma-separated list of severity levels that will cause failure')
    return parser.parse_args()


def wrap_text(text, width=120):
    """ Wraps the given text at approximately `width` characters without breaking words. """
    current_line = []
    current_len = 0
    for w in text.split():
        current_line.append(w)
        current_len += len(w)
        if current_len > width:
            yield ' '.join(current_line)
            current_line = []
            current_len = 0
    yield ' '.join(current_line)


def main():
    args = parse_args()
    fail_on = set(level.upper() for level in args.fail_on.split(',')) if args.fail_on else set()

    with open(Path(args.input_file), "r", encoding="utf-8") as f:
        data = json.load(f)

    if "results" not in data or not data["results"]:
        sys.exit(0)

    found_severe_issues = False

    for issue in data["results"]:
        path = issue.get("path")
        start_line = issue.get("start", {}).get("line", 1)
        message = issue.get("extra", {}).get("message", "No message")
        severity = issue.get("extra", {}).get("severity", "WARNING").upper()

        # Map Semgrep severity to GitHub annotation level
        level = {
            "ERROR": "error",
            "WARNING": "warning",
            "INFO": "notice",
        }.get(severity, "warning")  # default to warning if unknown severity

        # Extract additional metadata
        fix = issue.get("fix", "")
        metadata = issue.get("extra", {}).get("metadata", {})
        references = metadata.get("references", [])
        confidence = metadata.get("confidence", "Unknown")
        likelihood = metadata.get("likelihood", "Unknown")
        impact = metadata.get("impact", "Unknown")
        source = metadata.get("source", "Unknown")

        # Build the annotation message
        annotation_msg = "%0A".join(wrap_text(message))
        if fix:
            wrapped_fix = "%0A".join(wrap_text(fix))
            annotation_msg += f"%0ASuggested fix: {wrapped_fix}"

        # Add metadata information
        annotation_msg += "%0A%0AMetadata:"
        annotation_msg += f"%0A- Confidence: {confidence}"
        annotation_msg += f"%0A- Likelihood: {likelihood}"
        annotation_msg += f"%0A- Impact: {impact}"
        annotation_msg += f"%0A- Source: {source}"

        if references:
            ref_list = "%0A".join(f'- {r}' for r in references)
            annotation_msg += f"%0A%0AReferences:%0A{ref_list}"

        print(f"::{level} file={path},line={start_line}::{annotation_msg}")

        if severity in fail_on:
            found_severe_issues = True

    if found_severe_issues:
        sys.exit(1)


if __name__ == "__main__":
    main()
