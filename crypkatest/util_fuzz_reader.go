package crypkatest

import (
	"bytes"
	"encoding/binary"
)

const maxChunkSize = 1024 * 1024

// FuzzingChunks processes input and splits it into chunks, so fuzzing such scenarios is easier.
// All chunks are parts of input. No copying is done.
func FuzzingChunks(input []byte, receiver func(data []byte) (err error)) (err error) {
	for len(input) > 0 {
		rd := bytes.NewReader(input)
		rawSz, err := binary.ReadUvarint(rd)
		if err != nil {
			err = nil
			return nil
		}
		sz := int(rawSz % maxChunkSize)

		input = input[:rd.Len()]

		if sz > len(input) {
			sz = len(input)
		}

		err = receiver(input[:sz])
		if err != nil {
			return err
		}

		input = input[sz:]
	}

	return nil
}

// This function always yields n variable-sized chunks.
// It's valid for those chunks to be zero-sized.
// All chunks are parts of input. No copying is done.
func FuzzingNChunks(input []byte, n int, receiver func(data []byte) (err error)) (err error) {
	if n < 0 {
		panic("crypkatest: invalid n value provide")
	}
	if n == 0 {
		return
	}

	var resIndex int
	for len(input) > 0 && resIndex < n {
		resIndex++

		if resIndex == n-1 {
			receiver(input)
			break
		}

		rd := bytes.NewReader(input)
		rawSz, err := binary.ReadUvarint(rd)
		if err != nil {
			err = nil
			break
		}
		sz := int(rawSz % maxChunkSize)

		input = input[:rd.Len()]

		if sz > len(input) {
			sz = len(input)
		}

		err = receiver(input[:sz])
		if err != nil {
			return err
		}

		input = input[sz:]
	}

	for resIndex < n {
		resIndex++
		err = receiver(nil)
		if err != nil {
			return err
		}
	}

	return
}
