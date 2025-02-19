# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of the Sentry Scrubber library
- Core `SentryScrubber` class for scrubbing sensitive information from Sentry events
- Utility functions for data manipulation and string obfuscation:
  - `get_first_item`, `get_last_item` for list operations
  - `delete_item`, `get_value`, `extract_dict`, `modify_value` for dict operations
  - `distinct_by` for list deduplication
  - `obfuscate_string` for text anonymization
  - `order_by_utc_time` for timestamp-based sorting
- GitHub Actions workflows for:
  - PyTest execution
  - Ruff linting
  - Semgrep security analysis
  - Package publishing
- Test suite with coverage reporting

### Notes
- This code was extracted from [Tribler](https://github.com/Tribler/tribler/blob/release/7.15) as it was initially developed by me for Tribler
