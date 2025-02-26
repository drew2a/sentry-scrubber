# Sentry Scrubber

A lightweight Python library designed to protect sensitive information in Sentry events.

## Introduction

`sentry-scrubber` is a lightweight Python library designed to protect sensitive information in Sentry events. It
automatically detects and scrubs usernames, IP addresses, file paths, and other potentially sensitive data before events
are sent to Sentry.

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Configuration Options](#configuration-options)
4. [Integration with Sentry](#integration-with-sentry)
5. [Advanced Usage](#advanced-usage)
6. [API Reference](#api-reference)

## Installation

```bash
pip install sentry-scrubber
```

## Basic Usage

### Quick Start

```python
import sentry_sdk
from sentry_scrubber.scrubber import SentryScrubber

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
from sentry_scrubber.scrubber import SentryScrubber

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
# Result: {'user': {'username': '<redacted>'}, 'server_name': '<redacted>', 'contexts': {'os': {'home_dir': '/Users/<redacted>/Documents'}}, 'request': {'url': 'https://api.example.com/users/<redacted>', 'env': {'SERVER_ADDR': '<redacted>'}}}
```

### Scrubbing Text

```python
from sentry_scrubber.scrubber import SentryScrubber

scrubber = SentryScrubber()
sensitive_occurrences = set()

# Example text with sensitive information
text = "Error in file /home/username/app/main.py at line 42, reported from 192.168.1.1"

# Scrub the text
scrubbed_text = scrubber.scrub_text(text, sensitive_occurrences)
print(scrubbed_text)  # "Error in file /home/<redacted>/app/main.py at line 42, reported from <redacted>"
print(sensitive_occurrences)  # {'username'}
```

## Configuration Options

### Custom Home Folders

```python
from sentry_scrubber.scrubber import SentryScrubber

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
from sentry_scrubber.scrubber import SentryScrubber

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
from sentry_scrubber.scrubber import SentryScrubber

# Define markers that indicate sections to be removed
dict_markers = {
    'visibility': 'private'
}

scrubber = SentryScrubber(dict_markers_to_scrub=dict_markers)

# Example usage
event = {
    'public_info': 'This is public',
    'private_section': {
        'visibility': 'private',  # This will cause the entire 'private_section' to be redacted
        'secret_data': 'sensitive information'
    }
}

scrubbed = scrubber.scrub_event(event)
# Result: {'public_info': 'This is public', 'private_section': '<redacted>'}
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
scrubber.sensitive_strings.add({"john_doe", "secret_token_123"})

# Now any instance of these strings will be replaced in subsequent scrubs
text = "User john_doe used secret_token_123 to authenticate"
scrubbed = scrubber.scrub_text(text)
# Result: "User <redacted> used <redacted> to authenticate"
```

## Integration with Sentry

### Django Integration

```python
# settings.py
import sentry_sdk
from sentry_scrubber.scrubber import SentryScrubber
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

### Flask Integration

```python
# app.py
import sentry_sdk
from sentry_scrubber.scrubber import SentryScrubber
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

### FastAPI Integration

```python
# main.py
import sentry_sdk
from sentry_scrubber.scrubber import SentryScrubber
from fastapi import FastAPI

# Initialize scrubber
scrubber = SentryScrubber()

# Initialize Sentry
sentry_sdk.init(
    dsn="https://your-dsn@sentry.io/project",
    before_send=scrubber.scrub_event
)

app = FastAPI()
```

## API Reference

### SentryScrubber

```python
SentryScrubber(
    home_folders: Optional[set] = None,
dict_keys_for_scrub: Optional[set] = None,
dict_markers_to_scrub: Optional[dict] = None,
exclusions: Optional[set] = None,
scrub_ip: bool = True,
scrub_hash: bool = True,
scrub_folders: bool = True,
)
```

#### Methods

- `scrub_event(event: Optional[Dict[str, Any]], _=None) -> Optional[Dict[str, Any]]`: Scrubs a Sentry event
- `scrub_text(text: Optional[str], sensitive_occurrences: Set[str]) -> Optional[str]`: Scrubs sensitive information from
  text
- `scrub_entity_recursively(entity, sensitive_strings: set, depth=10)`: Recursively scrubs an entity

#### Properties

- `home_folders`: Set of folder names used to identify usernames in paths
- `dict_keys_for_scrub`: Set of dictionary keys whose values should be scrubbed
- `dict_markers_to_scrub`: Dictionary of markers that indicate sections to be redacted
- `event_fields_to_cut`: Set of fields to remove from events
- `exclusions`: Set of values to exclude from scrubbing
- `scrub_ip`: Flag to enable or disable IP scrubbing. Defaults to True.
- `scrub_hash`: Flag to enable or disable hash scrubbing. Defaults to True.
- `scrub_folders`: Flag to enable or disable folder scrubbing. Defaults to True.
            
