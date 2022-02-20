package crypka

import "errors"

var ErrKeyParseField = errors.New("crypka: filed to parse key")
var ErrInvalidSign = errors.New("crypka: sign is invalid")

var ErrAlreadyFinalized = errors.New("crypka: encryption was already finalized")

var ErrKeyNotMarshalable = errors.New("crypka: Key is not marshallable")

var ErrDecryptionAuthFiled = errors.New("crypka: Authentication of decrypted text filed. Message has been modified")
var ErrTooManyChunksEncrypted = errors.New("crypka: Encryptor can't encrypt securely any more chunks")

var ErrInvalidNonceType = errors.New("crypka: invalid NonceType value was provided")

var ErrInvalidRNGSeed = errors.New("crypka: given RNG seed is not valid")
var ErrRNGOutOfEntropy = errors.New("crypka: given RNG ran out of entropy and can't generate random data anymore")
var ErrInvalidKXDestination = errors.New("crypka: given KX destination buffer is not valid")

var ErrStreamChunkTooBig = errors.New("crypka: streamming encryption chunk is too big and won't be decrypted")
var ErrStreamCorrupted = errors.New("crypka: stream chunks were corrupted or reordered or stream was truncated or finalization chunks was not found")
var ErrUnsupportedCPKControlValue = errors.New("crpyka: found unknown CPK control value in decryption stream. data is either corrupted or decryptor version is too old")

var ErrIntEncodingError = errors.New("crypka: Filed to read encoded int")
