# `sentry-scrubber`

*A lightweight and flexible Python library for scrubbing sensitive information from Sentry events before they are sent to the server.*

## Features  
✅ Automatically detects and removes sensitive data (e.g., usernames, IP addresses, hashes).  
✅ Supports recursive scrubbing of complex event structures.  
✅ Customizable rules for scrubbing specific fields.  
✅ Seamless integration with Sentry SDK via `before_send` hook.  
✅ Minimal performance overhead.  

## Installation  

Install `sentry-scrubber` using `pip`:  

```sh
pip install sentry-scrubber
```

## Usage  

### Basic Integration with Sentry SDK  

```python
import sentry_sdk
from sentry_scrubber import SentryScrubber

scrubber = SentryScrubber()

sentry_sdk.init(
    dsn="your_sentry_dsn",
    before_send=scrubber.scrub_event  # Attach scrubbing function
)
```

### Manually Scrubbing an Event  

```python
event = {
    "user": {"username": "john_doe"},
    "request": {"ip_address": "192.168.1.1"},
    "extra": {"hash": "3030303030303030303030303030303030303030"},
}

scrubbed_event = scrubber.scrub_event(event)
print(scrubbed_event)
```

### Scrubbing Arbitrary Text  

```python
text = "A user logged in from 192.168.1.1"
scrubbed_text = scrubber.scrub_text(text)
print(scrubbed_text)  # Output: "A user logged in from <IP>"
```

## How It Works  

- Replaces sensitive values with placeholders (e.g., `<USERNAME>`, `<IP>`, `<HASH>`).  
- Uses regex patterns to detect and sanitize usernames, IPs, and hashes.  
- Recursively processes dictionaries and lists to ensure deep scrubbing.  
- Can be customized to add or exclude certain fields.  

## Customization  

You can configure the scrubber by modifying its attributes:  

```python
scrubber.dict_keys_for_scrub.append("api_key")  # Add a new sensitive key  
scrubber.event_fields_to_cut.append("debug_info")  # Remove specific event fields  
```

## License  

This project is licensed under the MIT License.  
