# JSON WebToken - This package provides JWT creation
# and verification functionality.
#
# (c) 2025 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/webtokens

import std/[times, json, strutils]
import ./api

type
  JwsHeader* = object
    alg*: string        # e.g. "HS256"
    kid*: string        # optional
    typ*: string = "JWT"

  JwsClaims* = JsonNode # arbitrary JSON payload

type
  JwsOptions* = object
    iat*: bool = true
      ## set iat (issued-at) automatically
    expIn*: int64 = 0
      ## seconds until expiry; 0 = no exp
    nbfAt*: Time
      ## optional not-before
    leeway*: int64 = 0
      ## verify leeway on time claims


proc resolveKey*(set: JwkSet, header: JwsHeader): tuple[alg: Alg, key: JwkItem] =
  ## Resolve JWK item and algorithm from set+header
  let alg = parseAlg(header.alg)
  if header.kid.len > 0:
    (alg, set.findByKid(header.kid))
  else:
    # Default: first item that matches intended alg (if provided)
    if set.count() == 0: raise newException(JwkError, "JWK set is empty")
    let it = set.itemByIndex(0)
    (alg, it)

proc sign*(set: JwkSet, header: JwsHeader, claims: JwsClaims, opt: JwsOptions = JwsOptions()): string =
  ## Sign: headers + claims -> compact JWT
  let (alg, key) = resolveKey(set, header)

  var b = newJwtBuilder()
  b.setKey(alg, key)

  # Headers
  if header.typ.len > 0: b.setHeader("typ", header.typ)
  if header.kid.len > 0: b.setHeader("kid", header.kid)

  # Claims
  if opt.iat: b.setIat()
  if opt.expIn > 0: b.setExpIn(opt.expIn)
  if opt.nbfAt.toUnix() > 0: b.setNbf(opt.nbfAt)

  # Merge provided claims
  for k, v in claims:
    case v.kind
    of JString: b.setClaim(k, v.getStr())
    of JInt: b.setClaim(k, int64(v.getInt()))
    of JFloat: b.setClaim(k, int64(v.getFloat()))
    of JBool: b.setClaim(k, v.getBool())
    else: b.setClaimJson(k, v)

  b.generate()

proc verify*(set: JwkSet, header: JwsHeader, token: string, opt: JwsOptions = JwsOptions()): JsonNode =
  ## Verify: compact JWT -> payload JSON; throws on failure
  let (alg, key) = resolveKey(set, header)
  var c = newJwtChecker()
  c.setKey(alg, key)
  if opt.leeway > 0:
    c.setLeeway(JWT_CLAIM_EXP, opt.leeway)
    c.setLeeway(JWT_CLAIM_NBF, opt.leeway)
    c.setLeeway(JWT_CLAIM_IAT, opt.leeway)
  discard c.verify(token) # throws on failure
  # Prefer cached payload from checker (fallback implemented in webtokens.nim)
  if c.payload.isNil:
    result = parsePayloadJson(token)
  else:
    result = c.payload
