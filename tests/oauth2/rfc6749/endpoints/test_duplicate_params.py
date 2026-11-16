# -*- coding: utf-8 -*-
"""Centralized duplicate-parameter rejection across server endpoints.

RFC 6749 Appendix B requires that request parameters MUST NOT be included
more than once. The check lives on BaseEndpoint and runs immediately after
the request is parsed, before any grant-type or downstream logic, so the
same parameter can never present one value to validation and another to
the code that consumes it.
"""
import json
from unittest import mock

from oauthlib.common import urlencode
from oauthlib.oauth2 import (
    BackendApplicationServer, IntrospectEndpoint, LegacyApplicationServer,
    RequestValidator, ResourceEndpoint, RevocationEndpoint, Server,
    WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase

FORM_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
TOKEN_URI = 'https://example.com/token'


class TokenEndpointDuplicateParamsTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = None
        self.server = Server(self.validator)

    def assert_duplicate_rejected(self, server, body, param):
        with self.assertRaises(errors.InvalidRequestError) as ctx:
            server.create_token_response(
                TOKEN_URI, body=body, headers=FORM_HEADERS)
        self.assertEqual(ctx.exception.error, 'invalid_request')
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(
            ctx.exception.description,
            'Duplicate %s parameter.' % param)
        # The raw request (including any token value) must never be echoed
        # back in the error response.
        self.assertNotIn(body, ctx.exception.json)
        self.validator.save_token.assert_not_called()

    def test_refresh_token_duplicate_refresh_token(self):
        body = ('grant_type=refresh_token&refresh_token=aaa'
                '&refresh_token=bbb&scope=foo')
        self.assert_duplicate_rejected(self.server, body, 'refresh_token')

    def test_refresh_token_duplicate_scope(self):
        body = ('grant_type=refresh_token&refresh_token=aaa'
                '&scope=foo&scope=bar')
        self.assert_duplicate_rejected(self.server, body, 'scope')

    def test_refresh_token_duplicate_grant_type(self):
        body = ('grant_type=refresh_token&grant_type=refresh_token'
                '&refresh_token=aaa')
        self.assert_duplicate_rejected(self.server, body, 'grant_type')

    def test_authorization_code_duplicate(self):
        body = ('grant_type=authorization_code&code=foo'
                '&client_id=bar&client_id=baz')
        self.assert_duplicate_rejected(self.server, body, 'client_id')

    def test_password_grant_duplicate(self):
        body = ('grant_type=password&username=foo&username=bar'
                '&password=secret')
        self.assert_duplicate_rejected(
            LegacyApplicationServer(self.validator), body, 'username')

    def test_client_credentials_grant_duplicate(self):
        body = 'grant_type=client_credentials&scope=foo&scope=bar'
        self.assert_duplicate_rejected(
            BackendApplicationServer(self.validator), body, 'scope')

    def test_unknown_parameter_duplicate_rejected(self):
        # Duplicates of parameters no grant type recognizes are rejected too,
        # so a newly introduced parameter is protected from day one.
        body = 'grant_type=refresh_token&refresh_token=aaa&custom=x&custom=y'
        self.assert_duplicate_rejected(self.server, body, 'custom')

    def test_duplicate_across_query_and_body_rejected(self):
        # The POST token endpoint forbids query strings already, but a
        # duplicate split across both sources must never be silently merged.
        uri = TOKEN_URI + '?refresh_token=from-query'
        body = 'grant_type=refresh_token&refresh_token=from-body'
        with self.assertRaises(errors.InvalidRequestError):
            self.server.create_token_response(
                uri, body=body, headers=FORM_HEADERS)

    def test_single_value_request_unchanged(self):
        # A normal, single-valued refresh request must keep working exactly
        # as before the centralized check was introduced.
        self.validator.client_authentication_required.return_value = False
        def set_client(client_id, request):
            request.client = mock.MagicMock()
            request.client.client_id = client_id
            return True
        self.validator.authenticate_client_id.side_effect = set_client
        self.validator.validate_grant_type.return_value = True
        self.validator.validate_refresh_token.return_value = True
        self.validator.get_original_scopes.return_value = ['foo']
        self.validator.save_token.return_value = None
        body = 'grant_type=refresh_token&refresh_token=aaa&scope=foo'
        headers, response, status = self.server.create_token_response(
            TOKEN_URI, body=body, headers=FORM_HEADERS)
        self.assertEqual(status, 200)
        payload = json.loads(response)
        self.assertIn('access_token', payload)
        self.assertEqual(headers['Content-Type'], 'application/json')


class AuthorizationEndpointDuplicateParamsTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(spec=RequestValidator)
        self.validator.get_default_redirect_uri.return_value = 'https://i.b/cb'
        self.server = WebApplicationServer(self.validator)

    def test_duplicate_query_param_is_fatal(self):
        uri = ('https://i.b/auth?response_type=code&client_id=foo'
               '&client_id=bar')
        with self.assertRaises(errors.InvalidRequestFatalError) as ctx:
            self.server.validate_authorization_request(uri)
        self.assertEqual(ctx.exception.error, 'invalid_request')
        self.assertEqual(
            ctx.exception.description, 'Duplicate client_id parameter.')

    def test_duplicate_body_param_is_fatal(self):
        body = 'response_type=code&client_id=foo&client_id=bar'
        with self.assertRaises(errors.InvalidRequestFatalError) as ctx:
            self.server.create_authorization_response(
                'https://i.b/auth', body=body, headers=FORM_HEADERS)
        self.assertEqual(
            ctx.exception.description, 'Duplicate client_id parameter.')


class RevocationEndpointDuplicateParamsTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(wraps=RequestValidator())
        self.validator.client_authentication_required.return_value = True
        self.validator.authenticate_client.return_value = True
        self.endpoint = RevocationEndpoint(self.validator)
        self.uri = 'https://example.com/revoke'

    def test_duplicate_token_rejected(self):
        body = urlencode([('token', 'secret-token'), ('token', 'other-token')])
        _headers, response, status = self.endpoint.create_revocation_response(
            self.uri, body=body, headers=FORM_HEADERS)
        payload = json.loads(response)
        self.assertEqual(status, 400)
        self.assertEqual(payload['error'], 'invalid_request')
        self.assertEqual(
            payload['error_description'], 'Duplicate token parameter.')
        # The token value itself must not appear in the error response.
        self.assertNotIn('secret-token', response)
        self.validator.revoke_token.assert_not_called()

    def test_single_token_request_unchanged(self):
        self.validator.revoke_token.return_value = True
        body = urlencode([('token', 'secret-token')])
        _h, response, status = self.endpoint.create_revocation_response(
            self.uri, body=body, headers=FORM_HEADERS)
        self.assertEqual(status, 200)
        self.assertEqual(response, '')


class IntrospectEndpointDuplicateParamsTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(wraps=RequestValidator())
        self.validator.client_authentication_required.return_value = True
        self.validator.authenticate_client.return_value = True
        self.endpoint = IntrospectEndpoint(self.validator)
        self.uri = 'https://example.com/introspect'

    def test_duplicate_token_rejected(self):
        body = urlencode([('token', 'secret-token'), ('token', 'other-token')])
        _h, response, status = self.endpoint.create_introspect_response(
            self.uri, body=body, headers=FORM_HEADERS)
        payload = json.loads(response)
        self.assertEqual(status, 400)
        self.assertEqual(payload['error'], 'invalid_request')
        self.assertEqual(
            payload['error_description'], 'Duplicate token parameter.')
        self.assertNotIn('secret-token', response)
        self.validator.introspect_token.assert_not_called()


class ResourceEndpointDuplicateParamsTest(TestCase):

    def setUp(self):
        self.validator = mock.MagicMock(wraps=RequestValidator())
        self.bearer = BearerToken(self.validator)
        self.endpoint = ResourceEndpoint(
            default_token='Bearer', token_types={'Bearer': self.bearer})

    def test_duplicate_access_token_rejected(self):
        uri = 'https://example.com/protected?access_token=a&access_token=b'
        with self.assertRaises(errors.InvalidRequestError) as ctx:
            self.endpoint.verify_request(uri)
        self.assertEqual(
            ctx.exception.description,
            'Duplicate access_token parameter.')
        self.validator.validate_bearer_token.assert_not_called()
