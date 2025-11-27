import std/[times, strutils, base64, json]

import unittest
import webtokens

var key: JwkItem
var token: string

test "can generate JWK set":
  # Generate a JWK Set with one random HMAC (oct) key
  let jwksJson = generateJwkSet(1, 32)
  let set = loadJwkSetFromJson($jwksJson)
  key = set.findByKid("hmac-key-0")
  let alg = parseAlg("HS256")

  assert jwksJson["keys"].len == 1
  assert jwksJson["keys"][0]["kty"].getStr() == "oct"
  assert key.itemKid() == "hmac-key-0"
  assert alg == JWT_ALG_HS256

test "can init JWT builder and generate token":
  # Initialize JWT Builder
  var builder = newJwtBuilder()
  builder.setKey(JWT_ALG_HS256, key)

  builder.setHeader("typ", "JWT")
  builder.setHeader("kid", key.itemKid())
  builder.setIss("example-app")
  builder.setSub("user123")

  builder.setExpIn(3600) # token expires in 1 hour

  # Generate the JWT
  token = builder.generate()
  assert token.len > 0

test "can verify generated token":
  var verifier = newJwtChecker()
  verifier.setKey(JWT_ALG_HS256, key)
  verifier.setLeeway(JWT_CLAIM_EXP, 5) # small clock skew
  assert verifier.verify(token)