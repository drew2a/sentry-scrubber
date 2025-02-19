"""
Script to generate GitHub Actions annotations from coverage data.

This script processes a JSON coverage report and generates GitHub-compatible warning
annotations for lines that are not covered by tests. It reads a JSON file containing
coverage statistics and outputs formatted warnings that will appear in GitHub PRs.

Usage:
    python annotate_coverage.py <path_to_json>

Arguments:
    path_to_json: Path to the JSON file containing coverage data

The JSON file should contain a 'src_stats' object with file paths as keys and
coverage statistics as values. Each file's statistics should include a 'violations'
list containing uncovered line numbers.

Example output:
    ::warning file=path/to/file.py,line=42::Line 42 is not covered by tests...
"""

import json
import sys

if len(sys.argv) != 2:
    print("Usage: python annotate_coverage.py <path_to_json>")
    sys.exit(1)

# Load the JSON file
json_file = sys.argv[1]
with open(json_file, 'r') as file:
    coverage_data = json.load(file)

src_stats = coverage_data.get("src_stats", {})
annotations = []

for file_path, stats in src_stats.items():
    violations = stats.get("violations", [])

    for line, _ in violations:
        message = (
            f"Line {line} is not covered by tests. Consider adding test cases to improve coverage."
        )

        annotation = (
            f"::warning file={file_path},line={line}::{message}"
        )
        print(annotation)