package crypka

import (
	"errors"
	"io"
)

const hashTagName = "shash"

var ErrHashNotSupported = errors.New("crypka: hash of given type is not supported")

// StructHashWriter manages process of writing arbitrary typed data into writer.
type StructHashWriter interface {
	WriteStruct(ctx HashContext, data interface{}, w io.Writer) (err error)
}

// StructHash consumes arbitrary input and produces hash from in form of byte slice.
type StructHasher interface {
	HashStruct(ctx HashContext, data interface{}) (res []byte, err error)
}

type HashableNew interface {
	HashSelf(w *HashableHelper) (err error)
}
