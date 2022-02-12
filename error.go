package crypka

import "errors"

var ErrKeyParseField = errors.New("crypka: filed to parse key")
var ErrInvalidSign = errors.New("crypka: sign is invalid")

var ErrKeyNotMarshalable = errors.New("crypka: Key is not marshallable")

var ErrDecryptionAuthFiled = errors.New("crypka: Authentication of decrypted text filed. Message has been modified")
var ErrTooManyChunksEncrypted = errors.New("crypka: Encryptor can't encrypt securely any more chunks")

var ErrInvalidNonceType = errors.New("crypka: invalid NonceType value was provided")
