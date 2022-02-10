package crypkatest

import (
	"bytes"
	"io"
)

func RNGReadBuffer(rng io.Reader, sz int) []byte {
	b := make([]byte, sz)
	_, err := io.ReadFull(rng, b)
	if err != nil {
		panic(err)
	}
	return b
}

func RNGReadBuffers(rng io.Reader, szs ...int) [][]byte {
	bb := make([][]byte, len(szs))
	for i, sz := range szs {
		bb[i] = RNGReadBuffer(rng, sz)
	}
	return bb
}

func BuffersEqual(lhs, rhs [][]byte) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i := range lhs {
		if !bytes.Equal(lhs[i], rhs[i]) {
			return false
		}
	}
	return true
}

type ChunkRunner struct {
	Sizes                   [][]int
	SameBufferPresets       [][][]byte
	DifferentBuffersPresets [][2][][]byte
	RNG                     io.Reader
}

func (cr *ChunkRunner) RunWithSameChunks(handler func(chunks [][]byte) (err error)) (err error) {
	for _, sizes := range cr.Sizes {
		chunks := RNGReadBuffers(cr.RNG, sizes...)
		err = handler(chunks)
		if err != nil {
			return
		}
	}

	for _, preset := range cr.SameBufferPresets {
		err = handler(preset)
		if err != nil {
			return
		}
	}

	return
}

func (cr *ChunkRunner) runWithDifferentChunks(handler func(lhs, rhs [][]byte) (err error)) (err error) {
	for _, sizes := range cr.Sizes {
		lhs := RNGReadBuffers(cr.RNG, sizes...)
		rhs := RNGReadBuffers(cr.RNG, sizes...)

		// is give up good behaviour?
		// in fact, for bigger data inputs
		// regen here?
		if BuffersEqual(lhs, rhs) {
			continue
		}

		err = handler(lhs, rhs)
		if err != nil {
			return
		}
	}

	for _, preset := range cr.DifferentBuffersPresets {
		lhs, rhs := preset[0], preset[1]

		if BuffersEqual(lhs, rhs) {
			panic("Preset for different values contains same values")
		}

		err = handler(lhs, rhs)
		if err != nil {
			return
		}
	}

	return
}
