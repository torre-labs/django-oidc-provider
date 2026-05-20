from django.test import SimpleTestCase
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse

from oidc_provider.lib.utils.redirect_uris import RedirectUriCollection
from oidc_provider.lib.utils.redirect_uris import _matches_wildcard_host
from oidc_provider.lib.utils.redirect_uris import matches_registered_redirect_uri
from oidc_provider.models import Client
from oidc_provider.models import ResponseType


class RedirectUriWildcardTestCase(TestCase):
    def setUp(self):
        self.authorize_url = reverse('oidc_provider:authorize')
        self.valid_local_redirect_uri = 'http://localhost:3000/callback?client_name=starrgate'
        self.valid_bunnyshell_redirect_uri = (
            'https://hybrid-bifrost-smoke.bunnyenv.com/callback?client_name=starrgate'
        )
        self.response_type, _ = ResponseType.objects.get_or_create(
            value='code',
            defaults={'description': 'Authorization Code Flow'},
        )
        self.oidc_client = Client.objects.create(
            client_id='wildcard-test',
            name='Wildcard Test',
            client_type='public',
            require_consent=False,
            reuse_consent=False,
        )
        self.oidc_client.response_types.add(self.response_type)
        self.oidc_client.redirect_uris = [
            self.valid_local_redirect_uri,
            'https://*.bunnyenv.com/callback?client_name=starrgate',
        ]
        self.oidc_client.save()

    def test_exact_http_redirect_uri_is_accepted(self):
        response = self.client.get(self.authorize_url, {
            'client_id': self.oidc_client.client_id,
            'response_type': 'code',
            'scope': 'openid email',
            'redirect_uri': self.valid_local_redirect_uri,
        })

        self.assertEqual(302, response.status_code)
        self.assertIn('/accounts/login/', response['Location'])

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_subdomain_wildcard_redirect_uri_is_accepted(self):
        response = self.client.get(self.authorize_url, {
            'client_id': self.oidc_client.client_id,
            'response_type': 'code',
            'scope': 'openid email',
            'redirect_uri': self.valid_bunnyshell_redirect_uri,
        })

        self.assertEqual(302, response.status_code)
        self.assertIn('/accounts/login/', response['Location'])

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_apex_wildcard_redirect_uri_is_rejected(self):
        response = self.client.get(self.authorize_url, {
            'client_id': self.oidc_client.client_id,
            'response_type': 'code',
            'scope': 'openid email',
            'redirect_uri': 'https://bunnyenv.com/callback?client_name=starrgate',
        })

        self.assertEqual(200, response.status_code)
        self.assertContains(response, 'Redirect URI Error')

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_host_outside_allowed_suffix_is_rejected(self):
        response = self.client.get(self.authorize_url, {
            'client_id': self.oidc_client.client_id,
            'response_type': 'code',
            'scope': 'openid email',
            'redirect_uri': 'https://evil.example.com/callback?client_name=starrgate',
        })

        self.assertEqual(200, response.status_code)
        self.assertContains(response, 'Redirect URI Error')

    def test_wildcard_redirect_uri_is_rejected_without_allowed_suffix_setting(self):
        response = self.client.get(self.authorize_url, {
            'client_id': self.oidc_client.client_id,
            'response_type': 'code',
            'scope': 'openid email',
            'redirect_uri': self.valid_bunnyshell_redirect_uri,
        })

        self.assertEqual(200, response.status_code)
        self.assertContains(response, 'Redirect URI Error')


class RedirectUriMatchingTestCase(SimpleTestCase):
    def test_redirect_uri_collection_keeps_exact_http_matching(self):
        redirect_uris = RedirectUriCollection([
            'http://localhost:3000/callback?client_name=starrgate',
        ])

        self.assertIn(
            'http://localhost:3000/callback?client_name=starrgate',
            redirect_uris,
        )

    def test_wildcard_host_requires_registered_wildcard(self):
        self.assertFalse(_matches_wildcard_host('bunnyenv.com', 'foo.bunnyenv.com'))

    def test_wildcard_host_requires_request_hostname(self):
        self.assertFalse(_matches_wildcard_host('*.bunnyenv.com', None))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_scheme_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'http://foo.bunnyenv.com/callback?client_name=starrgate',
            'https://*.bunnyenv.com/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_path_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://foo.bunnyenv.com/other?client_name=starrgate',
            'https://*.bunnyenv.com/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_params_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://foo.bunnyenv.com/callback?client_name=starrgate',
            'https://*.bunnyenv.com/callback;v1?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_query_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://foo.bunnyenv.com/callback?client_name=other',
            'https://*.bunnyenv.com/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_fragment_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://foo.bunnyenv.com/callback?client_name=starrgate#fragment',
            'https://*.bunnyenv.com/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_username_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://foo.bunnyenv.com/callback?client_name=starrgate',
            'https://user@*.bunnyenv.com/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_password_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://user@foo.bunnyenv.com/callback?client_name=starrgate',
            'https://user:secret@*.bunnyenv.com/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_port_mismatch(self):
        self.assertFalse(matches_registered_redirect_uri(
            'https://foo.bunnyenv.com/callback?client_name=starrgate',
            'https://*.bunnyenv.com:8443/callback?client_name=starrgate',
        ))

    @override_settings(OIDC_ALLOWED_REDIRECT_URI_WILDCARD_HOSTS=['bunnyenv.com'])
    def test_registered_redirect_uri_rejects_http_wildcard(self):
        self.assertFalse(matches_registered_redirect_uri(
            'http://foo.bunnyenv.com/callback?client_name=starrgate',
            'http://*.bunnyenv.com/callback?client_name=starrgate',
        ))
