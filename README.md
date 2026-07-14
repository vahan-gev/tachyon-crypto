# crypto

Cryptographic primitives for Tachyon — self-contained C, no OpenSSL dependency.
SHA-256, HMAC-SHA256, base64, constant-time compare, a CSPRNG, PBKDF2 password
hashing, and HS256 JWTs. Suitable for tokens, signing, integrity checks, login
credentials, and stateless auth.

## Install

```toml
# Tachyon.toml
deps = ["git+https://github.com/vahan-gev/tachyon-crypto#v0.1.0"]
```

```ts
import crypto.hash as crypto;
```

## What's in it

```ts
crypto.sha256("abc");                        // lowercase hex
crypto.hmacSha256(key, message);             // signing / webhooks
crypto.base64Encode(s);  crypto.base64Decode(s);
crypto.constantTimeEquals(a, b);             // timing-safe compare
crypto.randomToken(16);                      // CSPRNG bytes, hex — session ids, salts
```

### Passwords

`passwordHash` runs PBKDF2-HMAC-SHA256 with a fresh random salt and returns a
self-describing string (`pbkdf2_sha256$<iters>$<salt>$<hash>`) — store it as-is.
`passwordVerify` reads everything it needs back out of that string and compares
in constant time over the digest.

```ts
let stored = crypto.passwordHash("correct horse battery staple");
crypto.passwordVerify("correct horse battery staple", stored);   // true
crypto.passwordVerify("wrong", stored);                          // false
```

### JWTs (HS256)

```ts
let token = crypto.jwtSign(`{"sub":"42","exp":4102444800}`, secret);
let payload = crypto.jwtVerify(token, secret);   // string? — null if bad sig or expired
```

`jwtVerify` returns the payload JSON only when the signature matches `secret` and
the `exp` claim (unix seconds, if present) is in the future.

## Tested

PBKDF2 is verified against the RFC test vectors, the HS256 output against the
canonical jwt.io example token, SHA-256/HMAC against NIST/RFC vectors. Run
`tachyon test`.
