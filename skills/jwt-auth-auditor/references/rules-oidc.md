# Rule Set: Multi-Service Topologies, OIDC, and Distributed Verification

Load this file when more than one service verifies tokens, when an external
identity provider (Auth0, Keycloak, Cognito, Entra, Okta, etc.) is integrated,
or when an API gateway sits in front of services. For a single self-contained
service, report this set NOT-APPLICABLE except O07/O08 if OAuth flows appear.
Lane markers as in rules-tokens.md.

---

## Key distribution

### O01 No shared HS256 secret across services [Tier 1] [STANDARD]
- Check: if two or more services hold the same symmetric signing secret, each is
  a token factory; the power to verify equals the power to forge, and forgeries
  are indistinguishable. The first copy of a signing secret into a second
  service is the signal to move to RS256.
- Cite: RFC 8725; RFC 9700.

### O02 Public keys distributed via JWKS, not pasted key material [Tier 3] [STANDARD]
- Check: verifiers fetch keys from a `jwks_uri`; token headers carry `kid`.
- Cite: RFC 7517.

### O03 `kid` selects a key, never an algorithm [Tier 1] [STANDARD]
- Check: the verifier pins the algorithm itself and rejects unknown `kid`s.
  Letting the token's header choose the algorithm reopens the confusion attack.
- Cite: RFC 8725 Section 3.1.

### O04 JWKS is cached; rotation keeps two keys live [Tier 3] [STANDARD]
- Check: verifiers cache the key set and refetch on unknown `kid` (per-request
  fetch is a self-inflicted DoS on the auth server); rotation publishes the new
  key alongside the old until the longest-lived token expires.

---

## OIDC integration

### O05 Discovery used where available [Tier 4] [GUIDE]
- Check: clients bootstrap from `/.well-known/openid-configuration` (hyphen, not
  underscore) via a library rather than hardcoding six endpoints.
- Cite: OpenID Connect Discovery 1.0; RFC 8414.

### O06 ID tokens never sent to or accepted by the API [Tier 1] [STANDARD]
- Check: the API receives access tokens; an API that accepts an ID token is not
  checking `aud` (the ID token's audience is the client, not the API) and will
  accept ID tokens minted for any other client. Where supported, verify header
  `typ` is `at+jwt`.
- Cite: RFC 9068 Sections 2.1 and 4.

### O07 Browser/public clients use Authorization Code + PKCE [Tier 1] [STANDARD]
- Check: no implicit flow (tokens in URL fragments land in history and referrers),
  no password grant. RFC 9700 (BCP 240) removes both; PKCE is mandatory for
  public clients.
- Cite: RFC 7636; RFC 9700.

### O08 Being an authorization server is a buy, not a build [Tier 2] [GUIDE]
- Check: if the codebase implements its own authorization-code issuance, consent,
  or federation, flag it. RFC 6819 catalogues 13 attacks against the code flow
  alone. Verifying tokens as a relying party is a normal build task; issuing
  them for third parties is not.
- Verdict: ADVISORY with a pointed recommendation, not an automatic FAIL; a
  single-service issuer minting its own session JWTs (the rules-tokens.md model)
  is fine and is not "an authorization server" in this sense.

---

## Perimeter and service-to-service

### O09 Downstream services do not trust gateway-set identity headers [Tier 2] [STANDARD]
- Check: services do not authenticate requests off `X-User-Id`-style headers
  alone. That is secure only while the gateway is the sole network path, an
  assumption Kubernetes violates casually (port-forward, misconfigured LB,
  compromised neighbor pod). Preference order: forward the token and verify in
  each service (RS256 + JWKS makes this a local operation); mTLS from the
  gateway where that is impossible; header-stripping alone is never sufficient.
- Cite: NIST SP 800-207 (Zero Trust); OWASP Microservices Security.

### O10 Service-to-service calls carry verifiable identity [Tier 3] [STANDARD]
- Check: mTLS, SPIFFE/SPIRE, a service mesh, or RFC 8693 token exchange; network
  location is not a credential.
- Cite: NIST SP 800-207; RFC 8693.

### O11 Browser apps with an external IdP consider the BFF pattern [Tier 4] [GUIDE]
- Check: if OAuth tokens are held in the browser, note the BFF alternative
  (browser holds only an httpOnly session cookie; a confidential backend client
  holds the OAuth tokens; nothing for XSS to steal). ADVISORY, architecture
  suggestion, not a defect.
