from unittest.mock import Mock, patch


@patch('importlib.metadata.version', new=Mock(return_value="2.0.0"))
def test_version_success():
    """ Test version function """
    from sentry_scrubber import get_version
    assert get_version() == "2.0.0"


@patch('importlib.metadata.version', new=Mock(side_effect=ImportError))
def test_version_import_error():
    """ Test version function with ImportError """
    from sentry_scrubber import get_version
    assert get_version() == "1.0.0"
