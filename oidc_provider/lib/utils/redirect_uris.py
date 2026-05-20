try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from django.conf import settings as django_settings


def _normalize_hostname(hostname):
    return hostname.lower() if hostname else None


def _get_allowed_wildcard_hosts():
    allowed_suffixes = getattr(django_settings, 'OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS', None)

    if allowed_suffixes is None:
        allowed_suffixes = getattr(
            django_settings,
            'OIDC_EXTENSIONS_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS',
            []
        )

    return [_normalize_hostname(hostname) for hostname in allowed_suffixes]


def _is_allowed_wildcard_suffix(hostname):
    return hostname in _get_allowed_wildcard_hosts()


def _matches_wildcard_host(registered_hostname, request_hostname):
    if not registered_hostname or not request_hostname:
        return False

    if not registered_hostname.startswith('*.'):
        return False

    wildcard_suffix = _normalize_hostname(registered_hostname[2:])
    request_hostname = _normalize_hostname(request_hostname)

    if not wildcard_suffix or not _is_allowed_wildcard_suffix(wildcard_suffix):
        return False

    if request_hostname == wildcard_suffix:
        return False

    return request_hostname.endswith('.{0}'.format(wildcard_suffix))


def matches_registered_redirect_uri(request_redirect_uri, registered_redirect_uri):
    if request_redirect_uri == registered_redirect_uri:
        return True

    registered_uri = urlparse(registered_redirect_uri)
    request_uri = urlparse(request_redirect_uri)

    if registered_uri.scheme != request_uri.scheme:
        return False

    if registered_uri.path != request_uri.path:
        return False

    if registered_uri.params != request_uri.params:
        return False

    if registered_uri.query != request_uri.query:
        return False

    if registered_uri.fragment != request_uri.fragment:
        return False

    if registered_uri.username != request_uri.username:
        return False

    if registered_uri.password != request_uri.password:
        return False

    if registered_uri.port != request_uri.port:
        return False

    if registered_uri.scheme != 'https':
        return False

    return _matches_wildcard_host(registered_uri.hostname, request_uri.hostname)


class RedirectUriCollection(list):
    def __contains__(self, request_redirect_uri):
        return any(
            matches_registered_redirect_uri(request_redirect_uri, registered_redirect_uri)
            for registered_redirect_uri in self
        )
