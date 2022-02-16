package crypkatest

import (
	"bytes"
	"encoding/binary"
)

const maxChunkSize = 1024 * 1024

// FuzzingChunks processes input and splits it into chunks, so fuzzing such scenarios is easier.
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
