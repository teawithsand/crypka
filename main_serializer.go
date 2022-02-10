package crypka

import (
	"bytes"
	"io"
)

// Represents key, which may be serialized.
// Key serialized in such way should be parsable by algorithm.
//
// # Marshalling note
// Please note that keys shouldn't be marshalled in any other way.
// This is the only legit way, which provides security against leaking some redundant data.
type MarshalableKey interface {
	MarshalToWriter(w io.Writer) (err error)
}

func MarshalKey(key interface{}, w io.Writer) (err error) {
	mk, ok := key.(MarshalableKey)
	if !ok {
		err = ErrKeyNotMarshalable
		return
	}

	return mk.MarshalToWriter(w)
}

func MarshalKeyToSlice(key interface{}) (data []byte, err error) {
	mk, ok := key.(MarshalableKey)
	if !ok {
		err = ErrKeyNotMarshalable
		return
	}

	buf := bytes.NewBuffer(nil)
	err = mk.MarshalToWriter(buf)
	return buf.Bytes(), err
}
