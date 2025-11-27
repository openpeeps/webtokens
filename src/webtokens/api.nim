# JSON WebToken - This package provides JWT creation
# and verification functionality.
#
# (c) 2025 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/webtokens

import std/[times, strutils, base64, json]

import ./libjwt
export libjwt

#
# High-level JWT API
#

# libc free for buffers returned by C
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>".}

type
  JwtError* = object of CatchableError
  JwkError* = object of CatchableError

  Alg* = jwt_alg_t
  ClaimKind* = jwt_claims_t

  CryptoProvider* = jwt_crypto_provider_t

  JwkSet* = ref object
    p: ptr jwk_set_t

  JwkItem* = ref object
    p: ptr jwk_item_t
    owner: JwkSet   # keep set alive

  JwtBuilder* = ref object
    p: ptr jwt_builder_t

  JwtChecker* = ref object
    p: ptr jwt_checker_t
    payload*: JsonNode     # cache verified payload JSON

# Finalizers
proc finalize(b: JwtBuilder) =
  if b != nil and b.p != nil:
    jwt_builder_free(b.p)
    b.p = nil

proc finalize(c: JwtChecker) =
  if c != nil and c.p != nil:
    jwt_checker_free(c.p)
    c.p = nil

proc finalize(s: JwkSet) =
  if s != nil and s.p != nil:
    jwks_free(s.p)
    s.p = nil

# Helpers
proc raiseBuilder*(b: JwtBuilder, ctx: string) {.noinline.} =
  let msg = if b.p != nil: $jwt_builder_error_msg(b.p) else: ""
  raise newException(JwtError, ctx & (if msg.len > 0: ": " & msg else: ""))

proc raiseChecker*(c: JwtChecker, ctx: string) {.noinline.} =
  let msg = if c.p != nil: $jwt_checker_error_msg(c.p) else: ""
  raise newException(JwtError, ctx & (if msg.len > 0: ": " & msg else: ""))

proc raiseJwk*(s: JwkSet, ctx: string) {.noinline.} =
  let msg = if s.p != nil: $jwks_error_msg(s.p) else: ""
  raise newException(JwkError, ctx & (if msg.len > 0: ": " & msg else: ""))

proc toEpoch*(t: Time): int64 = toUnix(t)

# Alg helpers
proc `$`*(alg: Alg): string = $jwt_alg_str(alg)
proc parseAlg*(s: string): Alg = jwt_str_alg(s.cstring)

# Crypto provider helpers (optional)
proc currentCryptoProviderName*(): string = $jwt_get_crypto_ops()
proc currentCryptoProvider*(): CryptoProvider = jwt_get_crypto_ops_t()
proc setCryptoProvider*(name: string) =
  if jwt_set_crypto_ops(name.cstring) != 0:
    raise newException(JwtError, "Failed to set crypto provider: " & name)
proc setCryptoProvider*(prov: CryptoProvider) =
  if jwt_set_crypto_ops_t(prov) != 0:
    raise newException(JwtError, "Failed to set crypto provider enum")

# JWK Set API
proc loadJwkSetFromJson*(jsonStr: string): JwkSet =
  new(result, finalize)
  result.p = jwks_create(jsonStr.cstring)
  if result.p.isNil or jwks_error_any(result.p) != 0:
    result.raiseJwk("Failed to load JWK set from JSON")

proc loadJwkSetFromFile*(path: string): JwkSet =
  new(result, finalize)
  result.p = jwks_create_fromfile(path.cstring)
  if result.p.isNil or jwks_error_any(result.p) != 0:
    result.raiseJwk("Failed to load JWK set from file: " & path)

proc loadJwkSetFromUrl*(url: string; verifyTls: bool = true): JwkSet =
  new(result, finalize)
  result.p = jwks_create_fromurl(url.cstring, if verifyTls: 1 else: 0)
  if result.p.isNil or jwks_error_any(result.p) != 0:
    result.raiseJwk("Failed to load JWK set from URL: " & url)

proc count*(set: JwkSet): int =
  if set == nil or set.p == nil: 0
  else: int(jwks_item_count(set.p))

proc itemByIndex*(set: JwkSet, idx: int): JwkItem =
  if set == nil or set.p == nil: raise newException(JwkError, "Nil JwkSet")
  let it = jwks_item_get(set.p, csize_t(idx))
  if it.isNil: raise newException(JwkError, "JWK item not found at index " & $idx)
  new(result)
  result.p = it
  result.owner = set

proc findByKid*(set: JwkSet, kid: string): JwkItem =
  if set == nil or set.p == nil: raise newException(JwkError, "Nil JwkSet")
  let it = jwks_find_bykid(set.p, kid.cstring)
  if it.isNil: raise newException(JwkError, "JWK item with kid not found: " & kid)
  new(result)
  result.p = it
  result.owner = set

proc isPrivate*(it: JwkItem): bool = jwks_item_is_private(it.p) == 1
proc itemAlg*(it: JwkItem): Alg = jwks_item_alg(it.p)
proc itemKeyType*(it: JwkItem): jwk_key_type_t = jwks_item_kty(it.p)
proc itemUse*(it: JwkItem): jwk_pub_key_use_t = jwks_item_use(it.p)
proc itemKid*(it: JwkItem): string = $jwks_item_kid(it.p)
proc itemCurve*(it: JwkItem): string = $jwks_item_curve(it.p)
proc itemPem*(it: JwkItem): string = $jwks_item_pem(it.p)

# For OCT keys (HMAC secrets)
proc itemOctKey*(it: JwkItem): seq[byte] =
  var buf: ptr uint8 = nil
  var len: csize_t
  if jwks_item_key_oct(it.p, addr buf, addr len) != 0 or buf.isNil or len == 0:
    raise newException(JwkError, "Failed to extract OCT key")
  result = newSeq[byte](int(len))
  if len > 0:
    copyMem(addr result[0], buf, int(len))

# Builder API
proc newJwtBuilder*(): JwtBuilder =
  ## Creates a new JwtBuilder instance for building JWT tokens
  new(result, finalize)
  result.p = jwt_builder_new()
  if result.p.isNil:
    raise newException(JwtError, "Failed to create JwtBuilder")

proc setKey*(b: JwtBuilder, alg: Alg, key: JwkItem) =
  ## Sets the signing key for the JWT builder
  if b.p.isNil: raise newException(JwtError, "Nil JwtBuilder")
  if jwt_builder_setkey(b.p, alg, key.p) != 0:
    b.raiseBuilder("Failed to set key")

proc enableIat*(b: JwtBuilder, enable = true) =
  ## Enables or disables automatic "iat" (issued at) claim setting
  if jwt_builder_enable_iat(b.p, if enable: 1 else: 0) != 0:
    b.raiseBuilder("Failed to toggle iat")

proc setHeader*(b: JwtBuilder, name: string, value: string) =
  ## Sets a string header in the JWT.
  var v = jwtValueSetStr(name.cstring, value.cstring)
  let rc = jwt_builder_header_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set header: " & name)

proc setHeader*(b: JwtBuilder, name: string, value: bool) =
  ## Sets a boolean header in the JWT.
  var v = jwtValueSetBool(name.cstring, if value: 1 else: 0)
  let rc = jwt_builder_header_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set header: " & name)

proc setHeader*(b: JwtBuilder, name: string, value: int64) =
  ## Sets an integer header in the JWT.
  var v = jwtValueSetInt(name.cstring, value)
  let rc = jwt_builder_header_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set header: " & name)

proc setHeaderJson*(b: JwtBuilder, name: string, value: JsonNode) =
  ## Sets a JSON header in the JWT.
  var v = jwtValueSetJson(name.cstring, $value)
  let rc = jwt_builder_header_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set header JSON: " & name)

proc setClaim*(b: JwtBuilder, name: string, value: string) =
  ## Sets a string claim in the JWT.
  var v = jwtValueSetStr(name.cstring, value.cstring)
  let rc = jwt_builder_claim_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set claim: " & name)

proc setClaim*(b: JwtBuilder, name: string, value: int64) =
  ## Sets an integer claim in the JWT.
  var v = jwtValueSetInt(name.cstring, value)
  let rc = jwt_builder_claim_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set claim: " & name)

proc setClaim*(b: JwtBuilder, name: string, value: bool) =
  ## Sets a boolean claim in the JWT.
  var v = jwtValueSetBool(name.cstring, if value: 1 else: 0)
  let rc = jwt_builder_claim_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE: b.raiseBuilder("Failed to set claim: " & name)

proc setClaimJson*(b: JwtBuilder, name: string, value: JsonNode) =
  ## Sets a JSON `object`/`array` claim in the JWT
  assert value.kind in {JObject, JArray}, "Value must be a JSON object or array"
  var v = jwtValueSetJson(name.cstring, $value)
  let rc = jwt_builder_claim_set(b.p, addr v)
  if rc != JWT_VALUE_ERR_NONE:
    b.raiseBuilder("Failed to set JSON claim: " & name)

proc `[]=`*(b: JwtBuilder, name: string, value: string) {.inline.} =
  ## An alias for setClaim to set string claims.
  b.setClaim(name, value)

proc `[]=`*(b: JwtBuilder, name: string, value: int64) {.inline.} =
  ## An alias for setClaim to set integer claims.
  b.setClaim(name, value)

proc `[]=`*(b: JwtBuilder, name: string, value: bool) {.inline.} =
  ## An alias for setClaim to set boolean claims.
  b.setClaim(name, value)

proc `[]=`*(b: JwtBuilder, name: string, value: JsonNode) {.inline.} =
  ## An alias for setClaim to set string claims.
  b.setClaimJson(name, value)

proc setAud*(b: JwtBuilder, aud: string) =
  ## Sets the "aud" (audience) claim as a single string.
  b.setClaim("aud", aud)

proc setAud*(b: JwtBuilder, aud: openArray[string]) =
  ## Sets the "aud" (audience) claim as an array of strings.
  b.setClaimJson("aud", %*aud)

# Standard claims helpers
proc setIss*(b: JwtBuilder, iss: string) =
  ## Sets the "iss" (issuer) claim.
  b.setClaim("iss", iss)

proc setSub*(b: JwtBuilder, sub: string) =
  ## Sets the "sub" (subject) claim.
  b.setClaim("sub", sub)

proc setAud*(b: JwtBuilder, aud: string|seq[string]) =
  ## Sets the "aud" (audience) claim.
  when compiles(aud.toSeq):
    b.setClaimJson("aud", %*aud)
  else:
    b.setClaim("aud", $aud)

proc setExp*(b: JwtBuilder, exp: Time) =
  ## Sets the "exp" (expiration time) claim.
  b.setClaim("exp", toEpoch(exp))

proc setExpIn*(b: JwtBuilder, seconds: int64) =
  ## Sets the "exp" (expiration time) claim to current time + seconds.
  b.setClaim("exp", toEpoch(getTime()) + seconds)

proc setNbf*(b: JwtBuilder, nbf: Time) =
  ## Sets the "nbf" (not before) claim.
  b.setClaim("nbf", toEpoch(nbf))

proc setIat*(b: JwtBuilder, iat: Time = getTime()) =
  ## Sets the "iat" (issued at) claim.
  b.setClaim("iat", toEpoch(iat))

proc setJti*(b: JwtBuilder, jti: string) =
  ## Sets the "jti" (JWT ID) claim.
  b.setClaim("jti", jti)

proc timeOffset*(b: JwtBuilder, claim: ClaimKind, seconds: int64) =
  ## Sets a time offset (in seconds) for the specified claim.
  if jwt_builder_time_offset(b.p, claim, seconds) != 0:
    b.raiseBuilder("Failed to set time offset")

proc generate*(b: JwtBuilder): string =
  ## Generates the JWT token as a string.
  let cstr = jwt_builder_generate(b.p)
  if cstr.isNil:
    b.raiseBuilder("Failed to generate token")
  result = $cstr
  c_free(cstr) # free C-allocated buffer. if needed (libjwt uses malloc by default)

# Checker API
proc newJwtChecker*(): JwtChecker =
  new(result, finalize)
  result.p = jwt_checker_new()
  if result.p.isNil:
    raise newException(JwtError, "Failed to create JwtChecker")

proc setKey*(c: JwtChecker, alg: Alg, key: JwkItem) =
  if jwt_checker_setkey(c.p, alg, key.p) != 0:
    c.raiseChecker("Failed to set key")

proc b64urlDecode*(s: string): string =
  var t = s.replace('-', '+').replace('_', '/')
  let pad = (4 - (t.len mod 4)) mod 4
  if pad > 0: t.add(repeat('=', pad))
  result = base64.decode(t)

proc parsePayloadJson*(token: string): JsonNode =
  let parts = token.split('.')
  if parts.len < 2:
    raise newException(JwtError, "Invalid JWT format")
  let payloadStr = b64urlDecode(parts[1])
  result = parseJson(payloadStr)

proc setLeeway*(c: JwtChecker, claim: ClaimKind, seconds: int64) =
  ## Sets leeway (in seconds) for time-based claim verification.
  if jwt_checker_time_leeway(c.p, claim, seconds) != 0:
    c.raiseChecker("Failed to set leeway")

proc verify*(c: JwtChecker, token: string): bool =
  ## Verifies the JWT token signature and claims.
  let rc = jwt_checker_verify(c.p, token.cstring)
  if rc == 0:
    # Cache payload for claim fallback
    try:
      c.payload = parsePayloadJson(token)
    except CatchableError:
      c.payload = nil
    return true
  c.raiseChecker("Token verification failed")

# Map claim enum -> JSON key
proc claimKey(kind: ClaimKind): string =
  case kind
  of JWT_CLAIM_ISS: "iss"
  of JWT_CLAIM_SUB: "sub"
  of JWT_CLAIM_AUD: "aud"
  of JWT_CLAIM_JTI: "jti"
  of JWT_CLAIM_IAT: "iat"
  of JWT_CLAIM_EXP: "exp"
  of JWT_CLAIM_NBF: "nbf"
  else: ""

proc getClaim*(c: JwtChecker, kind: ClaimKind): string =
  ## Extracts the specified claim as a string. Falls back to cached payload JSON.
  let v = jwt_checker_claim_get(c.p, kind)
  
  # convert jwt_value_t to string
  if v != nil: return $v 
  if c.payload.isNil: return
  
  let key = claimKey(kind)
  if key.len == 0 or not c.payload.hasKey(key):
    return
  let n = c.payload[key]
  case n.kind
    of JString: n.getStr()
    of JInt: $n.getInt()
    of JFloat: $n.getFloat()
    else: $n  # arrays/objects -> JSON string

proc fromPayload*(c: JwtChecker, key: string): JsonNode =
  ## Extracts a claim from the cached payload JSON.
  if c.payload.hasKey(key):
    result = c.payload[key]

proc iss*(c: JwtChecker): string = c.getClaim(JWT_CLAIM_ISS)
proc sub*(c: JwtChecker): string = c.getClaim(JWT_CLAIM_SUB)
proc aud*(c: JwtChecker): string = c.getClaim(JWT_CLAIM_AUD)
proc jti*(c: JwtChecker): string = c.getClaim(JWT_CLAIM_JTI)

proc claimTime*(c: JwtChecker, kind: ClaimKind): Time =
  let s = c.getClaim(kind)
  if s.len > 0:
    let i = parseBiggestInt(s)
    return fromUnix(int64(i))
  if not c.payload.isNil:
    let key = claimKey(kind)
    if c.payload.hasKey(key):
      let n = c.payload[key]
      case n.kind
      of JInt: return fromUnix(int64(n.getInt()))
      of JFloat: return fromUnix(int64(n.getFloat()))
      else: discard
  fromUnix(0)
