<p align="center">
  👑 Nim bindings for LibJWT<br>
  JSON Web Token Library
</p>

<p align="center">
  <code>nimble install webtokens</code>
</p>

<p align="center">
  <a href="https://github.com/">API reference</a><br>
  <img src="https://github.com/openpeeps/webtokens/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/webtokens/workflows/docs/badge.svg" alt="Github Actions">
</p>

## About
This package provides Nim bindings for [LibJWT](https://github.com/benmcollins/libjwt), a C library that supports the following standards JWS, JWE, JWK, JWA and JWTs. It allows you to create, sign, verify, and decode JSON Web Tokens in your Nim applications.

### Prerequisites
Check the official [LibJWT installation guide](https://github.com/benmcollins/libjwt?tab=readme-ov-file#construction-build-prerequisites)


## Examples
Here is a simple example demonstrating how to create and sign a JSON Web Token (JWT) using HMAC SHA-256 algorithm with the `webtokens` Nim package.

### Create and Sign a Json Web Token
```nim
{.passL:"-L/opt/local/lib -ljwt", passC:"-I /opt/local/include".}

import std/[times, json]
import webtokens

# Generate a JWK Set with one random HMAC (oct) key
let jwksJson = generateJwkSet(1, 32)

let set = loadJwkSetFromJson($jwksJson)
let key = set.findByKid("hmac-key-0")
let alg = parseAlg("HS256")

# Initialize JWT Builder
var builder = newJwtBuilder()
builder.setKey(alg, key)

builder.setHeader("typ", "JWT")
builder.setHeader("kid", key.itemKid())
builder.setIss("example-app")
builder.setSub("user123")

builder.setExpIn(3600) # token expires in 1 hour

# Generate the token
let token = builder.generate()
echo "Generated JWT: ", token

# Now, you can use this token for authentication/authorization
var verifier = newJwtChecker()
verifier.setKey(alg, key)
verifier.setLeeway(JWT_CLAIM_EXP, 5) # small clock skew

if verifier.verify(token):
  echo "Verified OK!"
```

_todo more examples_

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/webtokens/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/webtokens/fork)
- 😎 [Get €20 in cloud credits from Hetzner](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4)

### 🎩 License
Made by [Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
