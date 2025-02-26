# Sentry Scrubber Cookbook

## Introduction

`sentry-scrubber` is a lightweight Python library designed to protect sensitive information in Sentry events. This
cookbook provides practical examples and recipes for using the library effectively in your applications.

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Configuration Options](#configuration-options)
4. [Advanced Scrubbing Techniques](#advanced-scrubbing-techniques)
5. [Integration Patterns](#integration-patterns)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

## Installation

```bash
pip install sentry-scrubber
```

## Basic Usage

### Quick Start

```python
import sentry_sdk
from scrubber import SentryScrubber

# Create a scrubber with default settings
scrubber = SentryScrubber()

# Initialize Sentry with the scrubber
sentry_sdk.init(
    dsn="https://your-dsn@sentry.io/project",
    before_send=scrubber.scrub_event
)
```

### Scrubbing Individual Events

```python
from scrubber import SentryScrubber

# Create a scrubber instance
scrubber = SentryScrubber()

# Example event with sensitive information
event = {
    "user": {"username": "john_doe"},
    "server_name": "johns-macbook",
    "contexts": {
        "os": {
            "home_dir": "/Users/john_doe/Documents"
        }
    },
    "request": {
        "url": "https://api.example.com/users/john_doe",
        "env": {
            "SERVER_ADDR": "192.168.1.1"
        }
    }
}

# Scrub the event
scrubbed_event = scrubber.scrub_event(event)
print(scrubbed_event)
# Result: {'user': {'username': '<oven>'}, 'server_name': '<shoulder>', 'contexts': {'os': {'home_dir': '/Users/<oven>/Documents'}}, 'request': {'url': 'https://api.example.com/users/<oven>', 'env': {'SERVER_ADDR': '<IP>'}}}
```

### Scrubbing Text

```python
from scrubber import SentryScrubber

scrubber = SentryScrubber()

# Example text with sensitive information
text = "Error in file /home/username/app/main.py at line 42, reported from 192.168.1.1"

# Scrub the text
scrubbed_text = scrubber.scrub_text(text)
print(scrubbed_text)  # "Error in file /home/<placeholder>/app/main.py at line 42, reported from <IP>"
```

## Configuration Options

### Custom Home Folders

```python
from scrubber import SentryScrubber

# Define custom home folders to detect usernames
custom_home_folders = {
    'users',
    'home',
    'projects',  # Custom folder
    'workspace'  # Custom folder
}

scrubber = SentryScrubber(home_folders=custom_home_folders)
```

### Sensitive Dictionary Keys

```python
from scrubber import SentryScrubber

# Define custom keys to scrub
custom_keys = {
    'USERNAME',
    'USERDOMAIN',
    'server_name',
    'COMPUTERNAME',
    'api_key',  # Custom sensitive key
    'auth_token',  # Custom sensitive key
    'password'  # Custom sensitive key
}

scrubber = SentryScrubber(dict_keys_for_scrub=custom_keys)
```

### Dictionary Markers for Removal

```python
from scrubber import SentryScrubber

# Define markers that indicate sections to be removed
dict_markers = {
    'security_level': 'confidential',
    'visibility': 'private'
}

scrubber = SentryScrubber(dict_markers_to_scrub=dict_markers)

# Example usage
event = {
    'public_info': 'This is public',
    'private_section': {
        'visibility': 'private',  # This will cause the entire 'private_section' to be emptied
        'secret_data': 'sensitive information'
    }
}

scrubbed = scrubber.scrub_event(event)
# Result: {'public_info': 'This is public', 'private_section': {}}
```

### Exclusions

```python
from scrubber import SentryScrubber

# Define values to be excluded from scrubbing
exclusions = {
    'local',
    '127.0.0.1',
    'localhost',  # Custom exclusion
    'admin',  # Custom exclusion
    'test_user'  # Custom exclusion
}

scrubber = SentryScrubber(exclusions=exclusions)
```

### Disable IP or Hash Scrubbing

```python
from scrubber import SentryScrubber

# Create a scrubber that doesn't scrub IP addresses
scrubber_no_ip = SentryScrubber(scrub_ip=False)

# Create a scrubber that doesn't scrub hash values
scrubber_no_hash = SentryScrubber(scrub_hash=False)

# Create a scrubber that scrubs neither IPs nor hashes
scrubber_minimal = SentryScrubber(scrub_ip=False, scrub_hash=False)
```

## Advanced Scrubbing Techniques

### Define Event Fields to Remove

```python
from scrubber import SentryScrubber

scrubber = SentryScrubber()

# Add fields to completely remove from events
scrubber.event_fields_to_cut.add('device')
scrubber.event_fields_to_cut.add('debug_data')
```

### Sensitive Information Pairs

```python
from scrubber import SentryScrubber

scrubber = SentryScrubber()

# Manually add sensitive information and corresponding placeholders
scrubber.add_sensitive_pair("john_doe", "<username>")
scrubber.add_sensitive_pair("secret_token_123", "<token>")

# Now any instance of these strings will be replaced in subsequent scrubs
text = "User john_doe used secret_token_123 to authenticate"
scrubbed = scrubber.scrub_text(text)
# Result: "User <username> used <token> to authenticate"
```

## Integration Patterns

### Integration with Django

```python
# settings.py
import sentry_sdk
from scrubber import SentryScrubber
from sentry_sdk.integrations.django import DjangoIntegration

scrubber = SentryScrubber(
    # Add custom configurations here
    dict_keys_for_scrub={'api_key', 'csrf_token', 'session_id', 'USERNAME'}
)

sentry_sdk.init(
    dsn="https://your-dsn@sentry.io/project",
    integrations=[DjangoIntegration()],
    before_send=scrubber.scrub_event
)
```

### Integration with Flask

```python
# app.py
import sentry_sdk
from scrubber import SentryScrubber
from sentry_sdk.integrations.flask import FlaskIntegration
from flask import Flask

# Initialize scrubber
scrubber = SentryScrubber()

# Initialize Sentry with Flask integration
sentry_sdk.init(
    dsn="https://your-dsn@sentry.io/project",
    integrations=[FlaskIntegration()],
    before_send=scrubber.scrub_event
)

app = Flask(__name__)
```

### Integration with Celery

```python
# celery_config.py
import sentry_sdk
from scrubber import SentryScrubber
from sentry_sdk.integrations.celery import CeleryIntegration

scrubber = SentryScrubber()

sentry_sdk.init(
    dsn="https://your-dsn@sentry.io/project",
    integrations=[CeleryIntegration()],
    before_send=scrubber.scrub_event
)
```

## Troubleshooting

### Debug Scrubbing Patterns

```python
from scrubber import SentryScrubber

scrubber = SentryScrubber()

# Print the compiled regular expressions for debugging
print("Folder patterns:")
for pattern in scrubber.re_folders:
    print(f" - {pattern.pattern}")

print(f"IP pattern: {scrubber.re_ip.pattern if scrubber.re_ip else 'disabled'}")
print(f"Hash pattern: {scrubber.re_hash.pattern if scrubber.re_hash else 'disabled'}")
```

### Inspect Sensitive Occurrences

```python
from scrubber import SentryScrubber

scrubber = SentryScrubber()

# Scrub some text
scrubber.scrub_text("/home/john_doe/app.log")
scrubber.scrub_text("Username: john_doe")

# Inspect what was found and stored
print("Sensitive information detected:")
for original, placeholder in scrubber.sensitive_occurrences.items():
    print(f" - '{original}' → '{placeholder}'")
```

### Test Scrubbing with Real-world Examples

```python
from scrubber import SentryScrubber

scrubber = SentryScrubber()

# Sample stack trace with sensitive information
stack_trace = """
Traceback (most recent call last):
  File "/Users/john_doe/myapp/main.py", line 42, in handle_request
    response = api_client.request(url, headers={'Authorization': 'Bearer abc123def456'})
  File "/Users/john_doe/myapp/api.py", line 15, in request
    return requests.get(url, headers=headers, timeout=10)
ConnectionError: Failed to connect to 192.168.1.100:8080
"""

scrubbed = scrubber.scrub_text(stack_trace)
print(scrubbed)
```

## Best Practices

### 1. Custom Scrubbing for Domain-specific Data

Extend the SentryScrubber class to handle domain-specific sensitive data:

```python
from scrubber import SentryScrubber
import re


class MedicalScrubber(SentryScrubber):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Add pattern for medical record numbers (example pattern)
        self.re_mrn = re.compile(r'MRN-\d{6}', re.I)

    def scrub_text(self, text):
        # First use the parent implementation
        text = super().scrub_text(text)

        # Then apply custom scrubbing
        if self.re_mrn and text:
            text = self.re_mrn.sub('<MEDICAL-RECORD-NUMBER>', text)

        return text
```

### 2. Balance Performance and Protection

For high-volume applications, consider optimizing scrubbing rules:

```python
from scrubber import SentryScrubber

# Create a minimal scrubber that only handles the most critical information
minimal_scrubber = SentryScrubber(
    # Only include essential home folders
    home_folders={'home', 'users', 'Documents and Settings'},

    # Only include critical keys
    dict_keys_for_scrub={'USERNAME', 'password', 'api_key'},

    # Disable hash scrubbing if not needed
    scrub_hash=False
)
```
