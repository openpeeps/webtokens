# JSON WebToken - This package provides JWT creation
# and verification functionality.
#
# (c) 2025 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/webtokens

import strutils, times

{.emit: """
#define JWT_EXPORT
""".}

const ext =
  when defined(linux):
    "so"
  elif defined(windows):
    "dll"
  else:
    "dylib"

{.push, importc, header:"<jwt.h>", dynlib: "libjwt." & ext.}

type
  time_t* = int64
  jwt_long_t* = int64 # Use int64 for long long, fallback to int if needed

  jwt_t* = object
    # Opaque pointer, use ptr jwt_t in FFI

  jwk_set_t* = object
    # Opaque pointer, use ptr jwk_set_t in FFI

  jwt_alg_t* {.size: sizeof(cint).} = enum
    JWT_ALG_NONE = 0,
    JWT_ALG_HS256,
    JWT_ALG_HS384,
    JWT_ALG_HS512,
    JWT_ALG_RS256,
    JWT_ALG_RS384,
    JWT_ALG_RS512,
    JWT_ALG_ES256,
    JWT_ALG_ES384,
    JWT_ALG_ES512,
    JWT_ALG_PS256,
    JWT_ALG_PS384,
    JWT_ALG_PS512,
    JWT_ALG_ES256K,
    JWT_ALG_EDDSA,
    JWT_ALG_INVAL

  jwt_crypto_provider_t* {.size: sizeof(cint).} = enum
    JWT_CRYPTO_OPS_NONE = 0,
    JWT_CRYPTO_OPS_OPENSSL,
    JWT_CRYPTO_OPS_GNUTLS,
    JWT_CRYPTO_OPS_MBEDTLS,
    JWT_CRYPTO_OPS_ANY

  jwk_key_type_t* {.size: sizeof(cint).} = enum
    JWK_KEY_TYPE_NONE = 0,
    JWK_KEY_TYPE_EC,
    JWK_KEY_TYPE_RSA,
    JWK_KEY_TYPE_OKP,
    JWK_KEY_TYPE_OCT

  jwk_pub_key_use_t* {.size: sizeof(cint).} = enum
    JWK_PUB_KEY_USE_NONE = 0,
    JWK_PUB_KEY_USE_SIG,
    JWK_PUB_KEY_USE_ENC

  jwk_key_op_t* {.size: sizeof(cint).} = enum
    JWK_KEY_OP_NONE = 0x0000,
    JWK_KEY_OP_SIGN = 0x0001,
    JWK_KEY_OP_VERIFY = 0x0002,
    JWK_KEY_OP_ENCRYPT = 0x0004,
    JWK_KEY_OP_DECRYPT = 0x0008,
    JWK_KEY_OP_WRAP = 0x0010,
    JWK_KEY_OP_UNWRAP = 0x0020,
    JWK_KEY_OP_DERIVE_KEY = 0x0040,
    JWK_KEY_OP_DERIVE_BITS = 0x0080,
    JWK_KEY_OP_INVALID = 0xffff

  jwt_value_type_t* {.size: sizeof(cint).} = enum
    JWT_VALUE_NONE = 0,
    JWT_VALUE_INT,
    JWT_VALUE_STR,
    JWT_VALUE_BOOL,
    JWT_VALUE_JSON,
    JWT_VALUE_INVALID

  jwt_value_error_t* {.size: sizeof(cint).} = enum
    JWT_VALUE_ERR_NONE = 0,
    JWT_VALUE_ERR_EXIST,
    JWT_VALUE_ERR_NOEXIST,
    JWT_VALUE_ERR_TYPE,
    JWT_VALUE_ERR_INVALID,
    JWT_VALUE_ERR_NOMEM

  JWTValue* = ptr jwt_value_t
    ## Pointer to jwt_value_t

  jwt_value_t* {.byCopy.} = object
    name*: cstring
    case `type`*: jwt_value_type_t
    of JWT_VALUE_INT:
      int_val*: jwt_long_t
    of JWT_VALUE_STR:
      str_val*: cstring
    of JWT_VALUE_BOOL:
      bool_val*: cint
    of JWT_VALUE_JSON:
      json_val*: cstring
    else:
      dummy*: pointer
    replace*: cint
    pretty*: cint
    error*: jwt_value_error_t

  jwk_item_t* = object
    # Opaque pointer, use ptr jwk_item_t in FFI

  jwt_malloc_t* = proc(size: csize_t): pointer {.cdecl.}
  jwt_free_t* = proc(p: pointer) {.cdecl.}

  jwt_config_t* = object
    key: ptr jwk_item_t
    alg: jwt_alg_t
    ctx: pointer

  jwt_callback_t* = proc(jwt: ptr jwt_t, config: ptr jwt_config_t): cint {.cdecl.}

  jwt_claims_t* {.size: sizeof(cint).} = enum
    JWT_CLAIM_ISS = 0x0001,
    JWT_CLAIM_SUB = 0x0002,
    JWT_CLAIM_AUD = 0x0004,
    JWT_CLAIM_EXP = 0x0008,
    JWT_CLAIM_NBF = 0x0010,
    JWT_CLAIM_IAT = 0x0020,
    JWT_CLAIM_JTI = 0x0040

  jwt_builder_t* = object
    # Opaque pointer, use ptr jwt_builder_t in FFI

  jwt_checker_t* = object
    # Opaque pointer, use ptr jwt_checker_t in FFI

# FFI declarations

proc jwt_get_alg*(jwt: ptr jwt_t): jwt_alg_t

proc jwt_builder_new*(): ptr jwt_builder_t
proc jwt_builder_free*(builder: ptr jwt_builder_t)
proc jwt_builder_error*(builder: ptr jwt_builder_t): cint
proc jwt_builder_error_msg*(builder: ptr jwt_builder_t): cstring
proc jwt_builder_error_clear*(builder: ptr jwt_builder_t)
proc jwt_builder_setkey*(builder: ptr jwt_builder_t, alg: jwt_alg_t, key: ptr jwk_item_t): cint
proc jwt_builder_enable_iat*(builder: ptr jwt_builder_t, enable: cint): cint
proc jwt_builder_setcb*(builder: ptr jwt_builder_t, cb: jwt_callback_t, ctx: pointer): cint
proc jwt_builder_getctx*(builder: ptr jwt_builder_t): pointer
proc jwt_builder_generate*(builder: ptr jwt_builder_t): cstring
proc jwt_builder_header_set*(builder: ptr jwt_builder_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_builder_header_get*(builder: ptr jwt_builder_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_builder_header_del*(builder: ptr jwt_builder_t, header: cstring): jwt_value_error_t
proc jwt_builder_claim_set*(builder: ptr jwt_builder_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_builder_claim_get*(builder: ptr jwt_builder_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_builder_claim_del*(builder: ptr jwt_builder_t, claim: cstring): jwt_value_error_t
proc jwt_builder_time_offset*(builder: ptr jwt_builder_t, claim: jwt_claims_t, secs: time_t): cint

proc jwt_checker_new*(): ptr jwt_checker_t
proc jwt_checker_free*(checker: ptr jwt_checker_t)
proc jwt_checker_error*(checker: ptr jwt_checker_t): cint
proc jwt_checker_error_msg*(checker: ptr jwt_checker_t): cstring
proc jwt_checker_error_clear*(checker: ptr jwt_checker_t)
proc jwt_checker_setkey*(checker: ptr jwt_checker_t, alg: jwt_alg_t, key: ptr jwk_item_t): cint
proc jwt_checker_setcb*(checker: ptr jwt_checker_t, cb: jwt_callback_t, ctx: pointer): cint
proc jwt_checker_getctx*(checker: ptr jwt_checker_t): pointer
proc jwt_checker_verify*(checker: ptr jwt_checker_t, token: cstring): cint
proc jwt_checker_claim_get*(checker: ptr jwt_checker_t, typ: jwt_claims_t): cstring
proc jwt_checker_claim_set*(checker: ptr jwt_checker_t, typ: jwt_claims_t, value: cstring): cint
proc jwt_checker_claim_del*(checker: ptr jwt_checker_t, typ: jwt_claims_t): cint
proc jwt_checker_time_leeway*(checker: ptr jwt_checker_t, claim: jwt_claims_t, secs: time_t): cint

proc jwt_header_set*(jwt: ptr jwt_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_header_get*(jwt: ptr jwt_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_header_del*(jwt: ptr jwt_t, header: cstring): jwt_value_error_t
proc jwt_claim_set*(jwt: ptr jwt_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_claim_get*(jwt: ptr jwt_t, value: ptr jwt_value_t): jwt_value_error_t
proc jwt_claim_del*(jwt: ptr jwt_t, claim: cstring): jwt_value_error_t

proc jwt_alg_str*(alg: jwt_alg_t): cstring
proc jwt_str_alg*(alg: cstring): jwt_alg_t

proc jwks_load*(jwk_set: ptr jwk_set_t, jwk_json_str: cstring): ptr jwk_set_t
proc jwks_load_strn*(jwk_set: ptr jwk_set_t, jwk_json_str: cstring, len: csize_t): ptr jwk_set_t
proc jwks_load_fromfile*(jwk_set: ptr jwk_set_t, file_name: cstring): ptr jwk_set_t
proc jwks_load_fromfp*(jwk_set: ptr jwk_set_t, input: pointer): ptr jwk_set_t
proc jwks_load_fromurl*(jwk_set: ptr jwk_set_t, url: cstring, verify: cint): ptr jwk_set_t
proc jwks_create*(jwk_json_str: cstring): ptr jwk_set_t
proc jwks_create_strn*(jwk_json_str: cstring, len: csize_t): ptr jwk_set_t
proc jwks_create_fromfile*(file_name: cstring): ptr jwk_set_t
proc jwks_create_fromfp*(input: pointer): ptr jwk_set_t
proc jwks_create_fromurl*(url: cstring, verify: cint): ptr jwk_set_t
proc jwks_error*(jwk_set: ptr jwk_set_t): cint
proc jwks_error_any*(jwk_set: ptr jwk_set_t): cint
proc jwks_error_msg*(jwk_set: ptr jwk_set_t): cstring
proc jwks_error_clear*(jwk_set: ptr jwk_set_t)
proc jwks_free*(jwk_set: ptr jwk_set_t)

proc jwks_item_get*(jwk_set: ptr jwk_set_t, index: csize_t): ptr jwk_item_t
proc jwks_find_bykid*(jwk_set: ptr jwk_set_t, kid: cstring): ptr jwk_item_t
proc jwks_item_is_private*(item: ptr jwk_item_t): cint
proc jwks_item_error*(item: ptr jwk_item_t): cint
proc jwks_item_error_msg*(item: ptr jwk_item_t): cstring
proc jwks_item_curve*(item: ptr jwk_item_t): cstring
proc jwks_item_kid*(item: ptr jwk_item_t): cstring
proc jwks_item_alg*(item: ptr jwk_item_t): jwt_alg_t
proc jwks_item_kty*(item: ptr jwk_item_t): jwk_key_type_t
proc jwks_item_use*(item: ptr jwk_item_t): jwk_pub_key_use_t
proc jwks_item_key_ops*(item: ptr jwk_item_t): jwk_key_op_t
proc jwks_item_pem*(item: ptr jwk_item_t): cstring
proc jwks_item_key_oct*(item: ptr jwk_item_t, buf: ptr ptr uint8, len: ptr csize_t): cint
proc jwks_item_key_bits*(item: ptr jwk_item_t): cint
proc jwks_item_free*(jwk_set: ptr jwk_set_t, index: csize_t): cint
proc jwks_item_free_all*(jwk_set: ptr jwk_set_t): cint
proc jwks_item_free_bad*(jwk_set: ptr jwk_set_t): cint
proc jwks_item_count*(jwk_set: ptr jwk_set_t): csize_t

proc jwt_set_alloc*(pmalloc: jwt_malloc_t, pfree: jwt_free_t): cint
proc jwt_get_alloc*(pmalloc: ptr jwt_malloc_t, pfree: ptr jwt_free_t)

proc jwt_get_crypto_ops*(): cstring
proc jwt_get_crypto_ops_t*(): jwt_crypto_provider_t
proc jwt_set_crypto_ops*(opname: cstring): cint
proc jwt_set_crypto_ops_t*(opname: jwt_crypto_provider_t): cint
proc jwt_crypto_ops_supports_jwk*(): cint
{.pop.}

# Helper macros as Nim templates
template jwt_set_GET_INT*(v: var jwt_value_t, n: cstring) =
  v.`type` = JWT_VALUE_INT
  v.name = n
  v.int_val = 0
  v.error = JWT_VALUE_ERR_NONE

template jwt_set_GET_STR*(v: var jwt_value_t, n: cstring) =
  v.`type` = JWT_VALUE_STR
  v.name = n
  v.str_val = nil
  v.error = JWT_VALUE_ERR_NONE

template jwt_set_GET_BOOL*(v: var jwt_value_t, n: cstring) =
  v.`type` = JWT_VALUE_BOOL
  v.name = n
  v.bool_val = 0
  v.error = JWT_VALUE_ERR_NONE

template jwt_set_GET_JSON*(v: var jwt_value_t, n: cstring) =
  v.`type` = JWT_VALUE_JSON
  v.pretty = 0
  v.name = n
  v.json_val = nil
  v.error = JWT_VALUE_ERR_NONE

proc jwtValueSetInt*(name: cstring, value: jwt_long_t): jwt_value_t =
  jwt_value_t(
    `type`: JWT_VALUE_INT,
    name: name,
    int_val: value,
    replace: 0,
    pretty: 0,
    error: JWT_VALUE_ERR_NONE
  )

proc jwtValueSetStr*(name: cstring, value: cstring): jwt_value_t =
  jwt_value_t(
    `type`: JWT_VALUE_STR,
    name: name,
    str_val: value,
    replace: 0,
    pretty: 0,
    error: JWT_VALUE_ERR_NONE
  )

proc jwtValueSetBool*(name: cstring, value: cint): jwt_value_t =
  jwt_value_t(
    `type`: JWT_VALUE_BOOL,
    name: name,
    bool_val: value,
    replace: 0,
    pretty: 0,
    error: JWT_VALUE_ERR_NONE
  )

proc jwtValueSetJson*(name: cstring, value: cstring): jwt_value_t =
  jwt_value_t(
    `type`: JWT_VALUE_JSON,
    name: name,
    json_val: value,
    replace: 0,
    pretty: 0,
    error: JWT_VALUE_ERR_NONE
  )