package crypka

// IMPLEMENTATION WARNING!
// Hashable must be implemented in predictable manner.
// This means that there should be(preferrably) no if statements in it's implementation.
type Hashable interface {
	HashSelf(w HashableWriter) (err error)
}

type HashableWriter interface {
	// Note: this function is not called on top level struct
	EnterStruct() (err error)
	ExitStruct() (err error)

	EnterSlice(length int) (err error)
	ExitSlice() (err error)

	// Note: it's up to HW implementation to provide protection against concatenating data buffers.
	WriteVarBytes(data []byte) (err error)

	// Note: it's up to caller here to provide protection against concatenating data buffers.
	// typically, by passing constant size buffers here.
	WriteConstBytes(data []byte) (err error)
}
