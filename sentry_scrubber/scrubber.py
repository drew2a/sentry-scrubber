import re
from typing import Any, Dict, List, Optional, Union

from sentry_scrubber.utils import delete_item, obfuscate_string

DEFAULT_EXCLUSIONS = {'local', '127.0.0.1'}

DEFAULT_KEYS_FOR_SCRUB = {'USERNAME', 'USERDOMAIN', 'server_name', 'COMPUTERNAME', 'key'}

# https://en.wikipedia.org/wiki/Home_directory
DEFAULT_HOME_FOLDERS = {
    'users',
    'usr',
    'home',
    'u01',
    'var',
    r'data\/media',
    r'WINNT\\Profiles',
    'Documents and Settings',
    'Users',
}


class SentryScrubber:
    """This class is responsible for scrubbing all sensitive
    and unnecessary information from Sentry events.
    """

    def __init__(
            self,
            home_folders: Optional[set] = None,
            dict_keys_for_scrub: Optional[set] = None,
            dict_markers_to_scrub: Optional[dict] = None,
            exclusions: Optional[set] = None,
            scrub_ip: bool = True,
            scrub_hash: bool = True,
    ):
        """
        Initializes the SentryScrubber with configurable parameters.

        Args:
            home_folders (Optional[set]): Set of home directory names to target for scrubbing.
            dict_keys_for_scrub (Optional[set]): Set of dictionary keys whose values should be scrubbed.
            dict_markers_to_scrub (Optional[dict]): Dictionary markers that indicate values to scrub.
            exclusions (Optional[set]): Set of values to exclude from scrubbing.
            scrub_ip (bool): Flag to enable or disable IP scrubbing. Defaults to True.
            scrub_hash (bool): Flag to enable or disable hash scrubbing. Defaults to True.

        Example:
            >>> scrubber = SentryScrubber(scrub_ip=False)
            >>> scrubbed_event = scrubber.scrub_event(event)
        """
        self.home_folders = home_folders or DEFAULT_HOME_FOLDERS
        self.dict_keys_for_scrub = dict_keys_for_scrub or DEFAULT_KEYS_FOR_SCRUB
        self.dict_markers_to_scrub = dict_markers_to_scrub or {}
        self.event_fields_to_cut = set()
        self.exclusions = exclusions or DEFAULT_EXCLUSIONS
        self.scrub_ip = scrub_ip
        self.scrub_hash = scrub_hash

        # this is the dict (key: sensitive_info, value: placeholder)
        self.sensitive_occurrences = {}

        # placeholders
        self.create_placeholder = lambda text: f'<{text}>'
        self.hash_placeholder = self.create_placeholder('hash')
        self.ip_placeholder = self.create_placeholder('IP')

        # compiled regular expressions
        self.re_folders = set()
        self.re_ip = None
        self.re_hash = None

        self._compile_re()

    def _compile_re(self):
        """
        Compiles all necessary regular expressions for scrubbing.

        Compiled Patterns:
            - Folder paths based on `home_folders`.
            - IP addresses if `scrub_ip` is enabled.
            - Hashes if `scrub_hash` is enabled.

        Example:
            >>> scrubber = SentryScrubber()
            >>> scrubber._compile_re()
        """
        slash = r'[/\\]'
        for folder in self.home_folders:
            for separator in [slash, slash * 2]:
                folder_pattern = rf'(?<={folder}{separator})[\w\s~]+(?={separator})'
                self.re_folders.add(re.compile(folder_pattern, re.I))

        if self.scrub_ip:
            self.re_ip = re.compile(r'(?<!\.)\b(\d{1,3}\.){3}\d{1,3}\b(?!\.)', re.I)
        if self.scrub_hash:
            self.re_hash = re.compile(r'\b[0-9a-f]{40}\b', re.I)

    def scrub_event(self, event, _=None):
        """
        Main method to scrub a Sentry event by removing sensitive and unnecessary information.

        Args:
            event (dict): A Sentry event represented as a dictionary.
            _ (Any, optional): Unused parameter for compatibility. Defaults to None.

        Returns:
            dict: The scrubbed Sentry event.

        Example:
            >>> scrubber = SentryScrubber()
            >>> scrubbed = scrubber.scrub_event(event)
        """
        if not event:
            return event

        # remove unnecessary fields
        for field_name in self.event_fields_to_cut:
            delete_item(event, field_name)

        # remove sensitive information
        scrubbed_event = self.scrub_entity_recursively(event)

        # this second call is necessary to complete the entities scrubbing
        # which were found at the end of the previous call
        scrubbed_event = self.scrub_entity_recursively(scrubbed_event)

        return scrubbed_event

    def scrub_text(self, text):
        """
        Replaces all sensitive information in the given text with corresponding placeholders.

        Sensitive Information:
            - IP addresses
            - User Names
            - 40-character hashes

        Args:
            text (str): The text to scrub.

        Returns:
            str: The scrubbed text.

        Example:
            >>> scrubber = SentryScrubber()
            >>> scrubbed_text = scrubber.scrub_text("User john_doe with IP 192.168.1.1 logged in.")
            >>> print(scrubbed_text)
            "User <hash> with IP <IP> logged in."
        """
        if text is None:
            return text

        def scrub_username(m):
            user_name = m.group(0)
            if user_name in self.exclusions:
                return user_name
            fake_username = obfuscate_string(user_name)
            placeholder = self.create_placeholder(fake_username)
            self.add_sensitive_pair(user_name, placeholder)
            return placeholder

        for regex in self.re_folders:
            text = regex.sub(scrub_username, text)

        if self.scrub_ip and self.re_ip:
            # cut an IP
            def scrub_ip(m):
                return self.ip_placeholder if m.group(0) not in self.exclusions else m.group(0)

            text = self.re_ip.sub(scrub_ip, text)

        if self.scrub_hash and self.re_hash:
            # cut hash
            text = self.re_hash.sub(self.hash_placeholder, text)

        # replace all sensitive occurrences in the whole string
        if self.sensitive_occurrences:
            escaped_sensitive_occurrences = [re.escape(user_name) for user_name in self.sensitive_occurrences]
            pattern = r'([^<]|^)\b(' + '|'.join(escaped_sensitive_occurrences) + r')\b'

            def scrub_value(m):
                if m.group(2) not in self.sensitive_occurrences:
                    return m.group(0)
                return m.group(1) + self.sensitive_occurrences[m.group(2)]

            text = re.sub(pattern, scrub_value, text)

        return text

    def scrub_entity_recursively(self, entity: Union[str, Dict, List, Any], depth=10):
        """
        Recursively traverses an entity to remove all sensitive information.

        Supports:
            1. Strings
            2. Dictionaries
            3. Lists

        All other data types are skipped.

        Args:
            entity (Union[str, Dict, List, Any]): The entity to scrub.
            depth (int, optional): The recursion depth limit. Defaults to 10.

        Returns:
            Union[str, Dict, List, Any]: The scrubbed entity.

        Example:
            >>> scrubber = SentryScrubber()
            >>> scrubbed = scrubber.scrub_entity_recursively(event_dict)
        """
        if depth < 0 or not entity:
            return entity

        depth -= 1

        if isinstance(entity, str):
            return self.scrub_text(entity)

        if isinstance(entity, list):
            return [self.scrub_entity_recursively(item, depth) for item in entity]

        if isinstance(entity, dict):
            result = {}
            for key, value in entity.items():
                if marker_value := self.dict_markers_to_scrub.get(key):
                    if value == marker_value:
                        result = {}
                        break

                if key in self.dict_keys_for_scrub and isinstance(value, str):
                    value = value.strip()
                    fake_value = obfuscate_string(value)
                    placeholder = self.create_placeholder(fake_value)
                    self.add_sensitive_pair(value, placeholder)
                    result[key] = placeholder
                else:
                    result[key] = self.scrub_entity_recursively(value, depth)
            return result

        return entity

    def add_sensitive_pair(self, text, placeholder):
        """
        Adds a sensitive text and its corresponding placeholder to the occurrences dictionary.

        Args:
            text (str): The sensitive text to be replaced.
            placeholder (str): The placeholder to replace the sensitive text.

        Example:
            >>> scrubber = SentryScrubber()
            >>> scrubber.add_sensitive_pair("john_doe", "<hashed_username>")
        """
        if not (text and text.strip()):  # Avoid replacing empty substrings
            return

        if text in self.sensitive_occurrences:
            return

        self.sensitive_occurrences[text] = placeholder
