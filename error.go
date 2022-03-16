package crypka

import "errors"

var ErrKeyParseField = errors.New("crypka: filed to parse key")
var ErrKeyNotMarshalable = errors.New("crypka: Key is not marshallable")

var ErrSignInvalid = errors.New("crypka: sign is invalid")

var ErrEncAlreadyFinalized = errors.New("crypka: encryption was already finalized")
var ErrEncAuthFiled = errors.New("crypka: Authentication of decrypted text filed. Message has been modified")
var ErrEncTooManyChunksEncrypted = errors.New("crypka: Encryptor can't encrypt securely any more chunks")
var ErrEncInvalidNonceType = errors.New("crypka: invalid NonceType value was provided")

var ErrEncStreamChunkTooBig = errors.New("crypka: streamming encryption chunk is too big and won't be decrypted")
var ErrEncStreamCorrupted = errors.New("crypka: stream chunks were corrupted or reordered or stream was truncated or finalization chunks was not found")
var ErrEncStreamUnsupportedCPK = errors.New("crpyka: found unknown CPK control value in decryption stream. data is either corrupted or decryptor version is too old")

var ErrRNGInvalidSeed = errors.New("crypka: given RNG seed is not valid")
var ErrRNGOutOfEntropy = errors.New("crypka: given RNG ran out of entropy and can't generate random data anymore")

var ErrKXInvalidDestination = errors.New("crypka: given KX destination buffer is not valid")
var ErrKXUnsupportedPart = errors.New("crypka: specified public or secret KX part is not supported by this algorithm")

var errIntEncodingError = errors.New("crypka: Filed to read encoded int")

var ErrPasswordHashMismatch = errors.New("crypka: password hash does not match password given")
var ErrPasswordHashParseFiled = errors.New("crypka: filed to parse password hash")
var ErrPasswordHashUnknownAlgo = errors.New("crypka: given password hash is encoded using unsupported algorithm")
var ErrPasswordHashParamMismatch = errors.New("crpyka: given password hash has different parameters compared to hasher, so it can't be processed")
