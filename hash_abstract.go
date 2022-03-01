package crypka

import (
	"errors"
	"io"
)

const hashTagName = "shash"

var ErrHashNotSupported = errors.New("crypka: hash of given type is not supported")

// StructHashWriter manages process of writing arbitrary typed data into writer.
//
// Note: it's not correct to use this multiple times on same signer.
// Security guarantees do not hold then.
// Use slice of values instead.
type StructHashWriter interface {
	WriteStruct(ctx HashContext, data interface{}, w io.Writer) (err error)
}

// StructHash consumes arbitrary input and produces hash from in form of byte slice.
//
// Note: when this type is too narrow and it does not fit the use case(like signing), StructHashWriter should be preferred.
type StructHasher interface {
	HashStruct(ctx HashContext, data interface{}) (res []byte, err error)
}

type HashableNew interface {
	HashSelf(w *HashableHelper) (err error)
}
