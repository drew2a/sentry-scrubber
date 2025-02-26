import re
from typing import Any, Dict, List, Optional, Set, TypeVar, Union

from sentry_scrubber.utils import delete_item

T = TypeVar('T')

DEFAULT_EXCLUSIONS = {'local', '127.0.0.1'}

DEFAULT_KEYS_FOR_SCRUB = {'USERNAME', 'USERDOMAIN', 'server_name', 'COMPUTERNAME'}

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
        self.placeholder = '<redacted>'

        self.sensitive_strings = set()

        # compiled regular expressions
        self._re_folders = set()
        self._re_ip = None
        self._re_hash = None

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
                self._re_folders.add(re.compile(folder_pattern, re.I))

        if self.scrub_ip:
            self._re_ip = re.compile(r'(?<!\.)\b(\d{1,3}\.){3}\d{1,3}\b(?!\.)', re.I)
        if self.scrub_hash:
            self._re_hash = re.compile(r'\b[0-9a-f]{40}\b', re.I)

    def scrub_event(self, event: Optional[Dict[str, Any]], _=None) -> Optional[Dict[str, Any]]:
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
        sensitive_strings = set(self.sensitive_strings)

        scrubbed_event = self.scrub_entity_recursively(event, sensitive_strings)

        # this second call is necessary to complete the entities scrubbing
        # which were found at the end of the previous call
        scrubbed_event = self.scrub_entity_recursively(scrubbed_event, sensitive_strings)

        return scrubbed_event

    def scrub_text(self, text: Optional[str], sensitive_occurrences: Set[str]) -> Optional[str]:
        """
        Replaces all sensitive information in the given text with corresponding placeholders.

        Sensitive Information:
            - IP addresses
            - User Names
            - 40-character hashes

        Args:
            text (str): The text to scrub.
            sensitive_occurrences (set): A set to store all sensitive occurrences.

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
            sensitive_occurrences.add(user_name)
            return self.placeholder

        for regex in self._re_folders:
            text = regex.sub(scrub_username, text)

        if self.scrub_ip and self._re_ip:
            def scrub_ip(m):
                return self.placeholder if m.group(0) not in self.exclusions else m.group(0)

            text = self._re_ip.sub(scrub_ip, text)

        if self.scrub_hash and self._re_hash:
            text = self._re_hash.sub(self.placeholder, text)

        # replace all sensitive occurrences in the whole string
        if sensitive_occurrences:
            escaped_sensitive_occurrences = (re.escape(user_name) for user_name in sensitive_occurrences)
            pattern = r'([^<]|^)\b(' + '|'.join(escaped_sensitive_occurrences) + r')\b'

            def scrub_value(m):
                if m.group(2) not in sensitive_occurrences:
                    return m.group(0)
                return m.group(1) + self.placeholder

            text = re.sub(pattern, scrub_value, text)

        return text

    def scrub_entity_recursively(self, entity: Union[str, Dict, List, Any], sensitive_strings: set, depth=10):
        """
        Recursively traverses an entity to remove all sensitive information.

        Supports:
            1. Strings
            2. Dictionaries
            3. Lists

        All other data types are skipped.

        Args:
            entity (Union[str, Dict, List, Any]): The entity to scrub.
            sensitive_strings (set): A set to store all sensitive string occurrences.
            depth (int, optional): The recursion depth limit. Defaults to 10.

        Returns:
            Union[str, Dict, List, Any]: The scrubbed entity.

        Example:
            >>> scrubber = SentryScrubber()
            >>> sensitive_strings = set()
            >>> scrubbed = scrubber.scrub_entity_recursively(event_dict, sensitive_strings)
        """
        if depth < 0 or not entity:
            # Base case: If depth exceeds limit or entity is empty, return it as is
            return entity

        depth -= 1

        if isinstance(entity, str):
            # If the entity is a string, scrub it directly
            return self.scrub_text(entity, sensitive_strings)

        if isinstance(entity, dict):
            # If the entity is a dictionary, scrub each key-value pair
            result = {}
            for key, value in entity.items():
                if not value:  # If the value is empty or None, retain it without scrubbing
                    result[key] = value
                    continue

                if marker_value := self.dict_markers_to_scrub.get(key):
                    should_be_scrubbed = value == marker_value
                    if should_be_scrubbed:
                        result = self.placeholder
                        break

                if key in self.dict_keys_for_scrub:
                    if isinstance(value, str):
                        if non_empty := value.strip():
                            sensitive_strings.add(non_empty)

                    result[key] = self.placeholder
                else:
                    result[key] = self.scrub_entity_recursively(value, sensitive_strings, depth)
            return result

        if isinstance(entity, list):
            return [self.scrub_entity_recursively(item, sensitive_strings, depth) for item in entity]
        if isinstance(entity, tuple):
            return tuple(self.scrub_entity_recursively(item, sensitive_strings, depth) for item in entity)

        return entity
