Duplicate request parameter handling
====================================

Background
----------

RFC 6749 Appendix B states that OAuth 2.0 request and response parameters
MUST NOT be included more than once. A request such as
``refresh_token=A&refresh_token=B`` is therefore malformed and must be
rejected, not reduced to a single value.

Why this was not blocked before
-------------------------------

``oauthlib.common.Request`` parses both the URL query string and the
``application/x-www-form-urlencoded`` body into parameter lists, then builds
its attribute map with ``dict(...)``. Converting a list of 2-tuples into a
dictionary keeps only one value for every repeated key, so after parsing the
request no longer carried any visible sign that a parameter had been sent
twice. Whichever value survived the dictionary conversion was the one used
by every downstream check and by the grant logic alike, while the discarded
value was invisible.

Duplicate-parameter checks did exist, but each grant type implemented its own
copy against its own short parameter whitelist:

* ``AuthorizationCodeGrant`` and ``ImplicitGrant`` checked the authorization
  request parameters;
* ``ClientCredentialsGrant`` and
  ``ResourceOwnerPasswordCredentialsGrant`` checked a subset of token request
  parameters;
* the RFC 8628 ``DeviceCodeGrant`` had its own two copies.

``RefreshTokenGrant`` had no check at all, and every whitelist missed
parameters the grant did not explicitly name. An attacker could therefore
send two copies of an unlisted parameter (or two copies of
``refresh_token`` on the refresh endpoint) and have one value silently
selected. This matches the repeated-parameter probing already visible in
production access logs.

Two earlier mitigation attempts did not close the hole:

* Gateway-level de-duplication only protected traffic that traversed the
  gateway; direct, internal calls to the authorization service bypassed it.
* Checks added inside individual business/grant handlers were written
  differently per entry point and the refresh endpoint was missed again.

In addition, when a framework passed a pre-parsed list of 2-tuples as the
body, ``Request`` converted it through ``to_unicode``/``dict`` before
``duplicate_params`` ever ran, collapsing the repetition during parsing.

Fix
---

The validation now exists in exactly one place,
``BaseEndpoint._raise_on_duplicate_params`` (and a fatal variant,
``_raise_on_fatal_duplicate_params``, for the authorization and device
authorization endpoints). Every server endpoint calls it immediately after
constructing the ``Request`` and before any grant-specific logic:

* token endpoint (all grant types, including refresh token and the RFC 8628
  device token exchange);
* authorization endpoint;
* token revocation endpoint;
* token introspection endpoint;
* device authorization endpoint (RFC 8628);
* protected resource endpoint;
* OpenID Connect userinfo endpoint.

Properties of the centralized check:

* Every parameter name is checked, not a per-grant whitelist, so a grant
  type added later is protected without writing any new validation.
* Repeated parameters are detected across the query string and the body and
  inside tuple-list bodies; the parsing-time dictionary collapse for
  tuple-list bodies was fixed in ``Request``.
* The error is the existing ``invalid_request`` error code with HTTP 400.
  No new error code was introduced. On authorization/device-authorization
  endpoints the existing fatal variant is used so the error is never sent
  through an untrusted redirect.
* The error description names only the duplicated parameter (for example
  ``Duplicate refresh_token parameter.``). The request body and any token
  values are never echoed into the response, so tokens cannot leak into
  client output or server logs through this path.
* Requests in which every parameter appears exactly once follow the same
  code path as before; normal single-parameter requests are unchanged.

The scattered, inconsistent checks inside the individual grant types were
removed so the endpoint layer is the single source of truth.

Security review conclusion
--------------------------

The previous design failed open: dictionary conversion destroyed the
evidence of duplication during parsing, and the remaining defenses were
optional, duplicated, whitelist-based, and absent from the refresh token
grant. The new design fails closed at a single chokepoint that every OAuth 2
server entry passes through, runs before any value is consumed, and uses an
existing error code without echoing request contents. Normal requests and
the behavior of every supported grant type are unchanged (the full existing
test suite continues to pass).
