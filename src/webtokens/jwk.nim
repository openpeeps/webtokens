# JSON WebToken - This package provides JWT creation
# and verification functionality.
#
# (c) 2025 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/webtokens

import std/[random, base64, json, strutils]
import ./api

randomize()

proc randomBytes(n: int): seq[byte] =
  # Generates n random bytes
  result = newSeq[byte](n)
  for i in 0..<n:
    result[i] = byte(rand(0..255))

proc base64urlEncode(data: seq[byte]): string =
  # Encodes data in base64url format (no padding)
  let b64 = base64.encode(cast[string](data))
  result = b64.replace("+", "-").replace("/", "_").replace("=", "")

proc generateOctJwk*(kid = "hmac-key", alg = "HS256", keyLen = 32): JsonNode =
  ## Generates a JWK (JSON Web Key) for HMAC (oct) with the specified key length
  ## `kid` is the key ID - a unique identifier for the key
  ## 
  ## `alg` is the algorithm (e.g., "HS256") associated with the key
  let secret = randomBytes(keyLen)
  let k = base64urlEncode(secret)
  result = %*{
    "kty": "oct",
    "k": k,
    "kid": kid,
    "alg": alg,
    "use": "sig"
  }

proc generateJwkSet*(count = 1, keyLen = 32): JsonNode =
  ## Generates a JWK Set with the specified number of HMAC (oct) keys
  ## `count` is the number of keys to generate. 
  ## 
  ## `keyLen` is the length of each key in bytes
  var keys = newSeq[JsonNode]()
  for i in 0..<count:
    keys.add(generateOctJwk(kid = "hmac-key-" & $i, keyLen = keyLen))
  result = %*{ "keys": keys }
