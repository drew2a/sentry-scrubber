import pytest

from scrubber import SentryScrubber


@pytest.fixture
def scrubber():
    return SentryScrubber()


FOLDERS_POSITIVE_MATCH = [
    '/home/username/some/',
    '/usr/local/path/',
    '/Users/username/some/',
    '/users/username/some/long_path',
    '/home/username/some/',
    '/data/media/username3/some/',
    'WINNT\\Profiles\\username\\some',
    'Documents and Settings\\username\\some',
    'C:\\Users\\Some User\\',
    'C:\\Users\\USERNAM~1\\',

    # double slashes (could be present as errors during a serialisation)
    'C:\\\\Users\\\\username\\\\',
    '//home//username//some//',

]

FOLDERS_NEGATIVE_MATCH = [
    '',
    'any text',
    '/home//some/',
]


@pytest.mark.parametrize('folder', FOLDERS_NEGATIVE_MATCH)
def test_patterns_folders_negative_match(folder: str, scrubber: SentryScrubber):
    """ Test that the scrubber does not match folders """
    assert not any(regex.search(folder) for regex in scrubber._re_folders)


@pytest.mark.parametrize('folder', FOLDERS_POSITIVE_MATCH)
def test_patterns_folders_positive_match(folder: str, scrubber: SentryScrubber):
    """ Test that the scrubber matches folders """
    assert any(regex.search(folder) for regex in scrubber._re_folders)


IP_POSITIVE_MATCH = [
    '127.0.0.1',
    '0.0.0.1',
    '0.100.0.1',
    '(0.100.0.1)'
]

IP_NEGATIVE_MATCH = [
    '0.0.0',
    '0.0.0.0.0',
    '0.1000.0.1',
    '0.a.0.1',
    '0123.0.0.1',
    '03.0.0.1234',
    'a0.0.0.1',
]


@pytest.mark.parametrize('ip', IP_NEGATIVE_MATCH)
def test_patterns_ip_negative_match(ip: str, scrubber: SentryScrubber):
    """ Test that the scrubber does not match IPs """
    assert not scrubber._re_ip.search(ip)


@pytest.mark.parametrize('ip', IP_POSITIVE_MATCH)
def test_patterns_ip_positive_match(ip: str, scrubber: SentryScrubber):
    """ Test that the scrubber matches IPs """
    assert scrubber._re_ip.search(ip)


HASH_POSITIVE_MATCH = [
    '3030303030303030303030303030303030303030',
    '0a30303030303030303030303030303030303030',
    'hash:3030303030303030303030303030303030303030'
]

HASH_NEGATIVE_MATCH = [
    '0a303030303030303030303030303030303030300',
    '0a3030303030303030303303030303030303030',
    'z030303030303030303030303030303030303030'
]


@pytest.mark.parametrize('h', HASH_NEGATIVE_MATCH)
def test_patterns_hash_negative_match(h: str, scrubber: SentryScrubber):
    """ Test that the scrubber does not match hashes """
    assert not scrubber._re_hash.search(h)


@pytest.mark.parametrize('h', HASH_POSITIVE_MATCH)
def test_patterns_hash_positive_match(h: str, scrubber: SentryScrubber):
    """ Test that the scrubber scrub hashes """
    assert scrubber._re_hash.search(h)


def test_scrub_path_negative_match(scrubber: SentryScrubber):
    """ Test that the scrubber does not scrub paths """
    sensitive_occurrences = set()
    assert scrubber.scrub_text('/usr/local/path/', sensitive_occurrences) == '/usr/local/path/'
    assert scrubber.scrub_text('some text', sensitive_occurrences) == 'some text'

    assert not sensitive_occurrences


def test_dict_markers_to_scrub(scrubber: SentryScrubber):
    scrubber.dict_markers_to_scrub = {'marker': 'top secret'}

    event = {
        'not secret information': 'any',
        'suspicious': {
            'information': 'but not secret',
            'just contains': 'top secret',
        },
        'secret information': {
            'marker': 'top secret',
            'any': 'information',
        }
    }

    actual = scrubber.scrub_event(event)
    expected = {
        'not secret information': 'any',
        'suspicious': {
            'information': 'but not secret',
            'just contains': 'top secret'
        },
        'secret information': '<redacted>'
    }

    assert actual == expected


def test_scrub_path_positive_match(scrubber: SentryScrubber):
    """ Test that the scrubber scrubs paths """
    sensitive_occurrences = set()
    assert scrubber.scrub_text('/users/user/apps', sensitive_occurrences) == '/users/<redacted>/apps'
    assert 'user' in sensitive_occurrences

    assert scrubber.scrub_text('/users/username/some/long_path',
                               sensitive_occurrences) == '/users/<redacted>/some/long_path'
    assert 'username' in sensitive_occurrences


def test_scrub_text_ip_negative_match(scrubber: SentryScrubber):
    """ Test that the scrubber does not scrub IPs """
    sensitive_occurrences = set()

    assert scrubber.scrub_text('127.0.0.1', sensitive_occurrences) == '127.0.0.1'
    assert scrubber.scrub_text('0.0.0', sensitive_occurrences) == '0.0.0'
    assert not sensitive_occurrences


def test_scrub_text_ip_positive_match(scrubber: SentryScrubber):
    """ Test that the scrubber scrubs IPs """
    sensitive_occurrences = set()

    assert scrubber.scrub_text('0.0.0.1', sensitive_occurrences) == '<redacted>'
    assert scrubber.scrub_text('0.100.0.1', sensitive_occurrences) == '<redacted>'

    assert not sensitive_occurrences


def test_scrub_text_ip_positive_match_disabled():
    """ Test that the scrubber does not scrub IPs """
    s = SentryScrubber(scrub_ip=False)
    sensitive_occurrences = set()

    assert s.scrub_text('0.0.0.1', sensitive_occurrences) == '0.0.0.1'
    assert not sensitive_occurrences


def test_scrub_text_hash_negative_match(scrubber: SentryScrubber):
    """ Test that the scrubber does not scrub hashes """
    sensitive_occurrences = set()

    too_long_hash = '1' * 41
    assert scrubber.scrub_text(too_long_hash, sensitive_occurrences) == too_long_hash
    too_short_hash = '2' * 39
    assert scrubber.scrub_text(too_short_hash, sensitive_occurrences) == too_short_hash


def test_scrub_text_hash_negative_match_disabled(scrubber: SentryScrubber):
    """ Test that the scrubber does not scrub hashes """
    sensitive_occurrences = set()
    s = SentryScrubber(scrub_hash=False)
    hash_text = '3030303030303030303030303030303030303030'
    assert s.scrub_text(hash_text, sensitive_occurrences) == hash_text
    assert not sensitive_occurrences


def test_folders_disabled():
    """ Test that the scrubber does not scrub folders """
    sensitive_occurrences = set()
    s = SentryScrubber(scrub_folders=False)
    assert s.scrub_text('usr/someuser/path', sensitive_occurrences) == 'usr/someuser/path'
    assert not sensitive_occurrences


def test_scrub_text_hash_positive_match(scrubber: SentryScrubber):
    """ Test that the scrubber scrubs hashes """
    sensitive_occurrences = set()

    assert scrubber.scrub_text('3' * 40, sensitive_occurrences) == '<redacted>'
    assert scrubber.scrub_text('hash:' + '4' * 40, sensitive_occurrences) == 'hash:<redacted>'

    assert not sensitive_occurrences


def test_scrub_text_complex_string(scrubber):
    """ Test that the scrubber scrubs complex strings """
    source = (
        'this is a string that has been sent from '
        '192.168.1.1(3030303030303030303030303030303030303030) '
        'located at usr/someuser/path on '
        "someuser's machine(someuser_with_postfix)"
    )
    sensitive_occurrences = set()

    actual = scrubber.scrub_text(source, sensitive_occurrences)

    assert actual == ('this is a string that has been sent from '
                      '<redacted>(<redacted>) '
                      'located at usr/<redacted>/path on '
                      "<redacted>'s machine(someuser_with_postfix)")

    assert 'someuser' in sensitive_occurrences
    assert scrubber.scrub_text('someuser', sensitive_occurrences) == '<redacted>'


def test_scrub_simple_event(scrubber: SentryScrubber):
    """ Test that the scrubber scrubs simple events """
    assert scrubber.scrub_event(None) is None
    assert scrubber.scrub_event({}) == {}
    assert scrubber.scrub_event({'some': 'field'}) == {'some': 'field'}


def test_scrub_event(scrubber: SentryScrubber):
    """ Test that the scrubber scrubs events """
    event = {
        'the very first item': 'username',
        'server_name': 'userhost',
        'contexts': {
            'reporter': {
                'any': {
                    'USERNAME': 'User Name',
                    'USERDOMAIN_ROAMINGPROFILE': 'userhost',
                    'PATH': '/users/username/apps',
                    'TMP_WIN': r'C:\Users\USERNAM~1\AppData\Local\Temp',
                    'USERDOMAIN': ' USER-DOMAIN',  # it is a corner case when there is a space before a text
                    'COMPUTERNAME': 'Computer name',
                },
                'stacktrace': [
                    'Traceback (most recent call last):',
                    'File "/Users/username/Tribler/tribler/src/tribler-gui/tribler_gui/"',
                ],
                'sysinfo': {'sys.path': ['/Users/username/Tribler/', '/Users/username/', '.']},
            },
            'tuple': ('tuple', 'data'),
        },
        'extra': {'sys_argv': ['/Users/username/Tribler']},
        'logentry': {'message': 'Exception with username', 'params': ['Traceback File: /Users/username/Tribler/']},
        'breadcrumbs': {
            'values': [
                {'type': 'log', 'message': 'Traceback File: /Users/username/Tribler/', 'timestamp': '1'},
                {'type': 'log', 'message': 'IP: 192.168.1.1', 'timestamp': '2'},
            ]
        },
    }
    assert scrubber.scrub_event(event) == {
        'the very first item': '<redacted>',
        'server_name': '<redacted>',
        'contexts': {
            'reporter': {
                'any': {
                    'USERNAME': '<redacted>',
                    'USERDOMAIN_ROAMINGPROFILE': '<redacted>',
                    'PATH': '/users/<redacted>/apps',
                    'TMP_WIN': 'C:\\Users\\<redacted>\\AppData\\Local\\Temp',
                    'USERDOMAIN': '<redacted>',
                    'COMPUTERNAME': '<redacted>',
                },
                'stacktrace': [
                    'Traceback (most recent call last):',
                    'File "/Users/<redacted>/Tribler/tribler/src/tribler-gui/tribler_gui/"',
                ],
                'sysinfo': {
                    'sys.path': [
                        '/Users/<redacted>/Tribler/',
                        '/Users/<redacted>/',
                        '.',
                    ]
                },
            },
            'tuple': ('tuple', 'data'),
        },
        'logentry': {
            'message': 'Exception with <redacted>',
            'params': ['Traceback File: /Users/<redacted>/Tribler/'],
        },
        'extra': {'sys_argv': ['/Users/<redacted>/Tribler']},
        'breadcrumbs': {
            'values': [
                {
                    'type': 'log',
                    'message': 'Traceback File: /Users/<redacted>/Tribler/',
                    'timestamp': '1',
                },
                {'type': 'log', 'message': 'IP: <redacted>', 'timestamp': '2'},
            ]
        },
    }


def test_entities_recursively(scrubber):
    """ Test that the scrubber scrubs entities recursively """
    sensitive_strings = set()

    # positive
    assert scrubber.scrub_entity_recursively(None, sensitive_strings) is None
    assert scrubber.scrub_entity_recursively({}, sensitive_strings) == {}
    assert scrubber.scrub_entity_recursively([], sensitive_strings) == []
    assert scrubber.scrub_entity_recursively('', sensitive_strings) == ''
    assert scrubber.scrub_entity_recursively(42, sensitive_strings) == 42

    event = {
        'some': {
            'value': [
                {
                    'path': '/Users/username/Tribler'
                }
            ]
        }
    }
    assert scrubber.scrub_entity_recursively(event, sensitive_strings) == {
        'some': {'value': [{'path': '/Users/<redacted>/Tribler'}]}
    }
    # stop on depth
    assert scrubber.scrub_entity_recursively(event, sensitive_strings) != event
    assert scrubber.scrub_entity_recursively(event, sensitive_strings, depth=2) == event


def test_scrub_unnecessary_fields(scrubber):
    """ Test that the scrubber scrubs unnecessary fields """
    # default
    assert scrubber.scrub_event({'default': 'field'}) == {'default': 'field'}

    # custom
    custom_scrubber = SentryScrubber()
    custom_scrubber.event_fields_to_cut = {'new', 'default'}
    assert custom_scrubber.scrub_event({'default': 'event', 'new': 'field', 'modules': {}}) == {'modules': {}}


def test_scrub_text_none(scrubber):
    sensitive_occurrences = set()

    assert scrubber.scrub_text(None, sensitive_occurrences) is None


def test_scrub_entity_none(scrubber):
    sensitive_string = set()

    assert scrubber.scrub_entity_recursively(None, sensitive_string) is None


def test_scrub_entity_empty_dict(scrubber):
    sensitive_string = set()

    assert scrubber.scrub_entity_recursively({}, sensitive_string) == {}


@pytest.mark.parametrize("sensitive_value", [
    [1],
    {'some': 'value'},
    ('some', 'value')
])
def test_scrub_entity_with_complex_structure(sensitive_value, scrubber):
    """ Test that the scrubber scrubs entities with complex structures """
    event = {'key': sensitive_value}
    scrubber.dict_keys_for_scrub = {'key'}

    sensitive_string = set()

    actual = scrubber.scrub_entity_recursively(event, sensitive_string)
    assert actual == {'key': '<redacted>'}


def test_scrub_entity_given_dict(scrubber):
    given = {
        'PATH': '/home/username/some/',
        'USERDOMAIN': 'UD',
        'USERNAME': 'U',
        'REPEATED': 'user username UD U',
        'key': ''
    }
    sensitive_string = set()

    actual = scrubber.scrub_entity_recursively(given, sensitive_string)
    expected = {
        'PATH': '/home/<redacted>/some/',
        'REPEATED': 'user <redacted> <redacted> <redacted>',
        'USERDOMAIN': '<redacted>',
        'USERNAME': '<redacted>',
        'key': ''
    }
    assert actual == expected

    assert 'username' in sensitive_string
    assert 'UD' in sensitive_string
    assert 'U' in sensitive_string
    assert '' not in sensitive_string


def test_scrub_list(scrubber):
    sensitive_string = set()

    assert scrubber.scrub_entity_recursively(None, sensitive_string) is None
    assert scrubber.scrub_entity_recursively([], sensitive_string) == []

    actual = scrubber.scrub_entity_recursively(['/home/username/some/'], sensitive_string)
    assert actual == ['/home/<redacted>/some/']
    assert 'username' in sensitive_string
