package crypka

import "errors"

var ErrKeyParseField = errors.New("crypka: filed to parse key")
var ErrInvalidSign = errors.New("crypka: sign is invalid")

var ErrHMACKeyTooShort = errors.New("crypka: HMAC key too short")
var ErrHMACKeyTooLong = errors.New("crypka: HMAC key too long")

var ErrKeyNotMarshalable = errors.New("crypka: Key is not marshallable")

var ErrDecryptionAuthFiled = errors.New("crypka: Authentication of decrypted text filed. Message has been modified")
