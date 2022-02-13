package crypka

import "io"

// IMPLEMENTATION WARNING!
// Hashable must be implemented in predictable manner.
// In other words: each structure data must match
// Each slice has to be written using prefix length, and appropriate separation must be used in order to prevent moving data between fields(and resulting in same hash).
//
// TODO(teawithsand): util, which makes hashing struct either automatic or simplifies doing it correctly.
type Hashable interface {
	HashSelf(w io.Writer) (err error)
}
