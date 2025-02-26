def get_version():
    try:
        from importlib.metadata import version
        return version("sentry-scrubber")
    except ImportError:
        return "1.0.0"

__version__ = get_version()