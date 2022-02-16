package crypka

func newCPKStreamDecryptor(inner Decryptor, maxChunkSize int) *cpkStreamDecryptor {
	enc := &cpkStreamDecryptor{
		inner:        inner,
		maxChunkSize: maxChunkSize,
		chunkCounter: 1,

		// chunkSizeEncoding:    Byte4,
		// chunkCounterEncoding: Byte4,
	}

	return enc
}

type cpkStreamDecryptor struct {
	inner Decryptor

	maxChunkSize int

	chunkCounterEncoding intEncoding
	chunkSizeEncoding    intEncoding

	chunkCounter uint64

	dataBuffer    []byte
	restChunkSize int

	cachedError error
}

func (dec *cpkStreamDecryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: true,
		EncType:              EncTypeStream,
	}
}

func (dec *cpkStreamDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	res = appendTo

	for {
		if len(in) == 0 {
			return
		}

		if dec.chunkCounter == 0 {
			err = ErrStreamCorrupted
			dec.cachedError = ErrStreamCorrupted
			return
		}

		for dec.restChunkSize == 0 {
			if len(in) == 0 {
				return
			}

			var chunkSize uint64
			var sz int

			dec.dataBuffer = append(dec.dataBuffer, in[0])
			in = in[1:]

			chunkSize, sz, err = dec.chunkSizeEncoding.DecodeAtStart(dec.dataBuffer)
			if err != nil {
				err = nil
				continue
			}

			// zero chunks are not allowed
			if chunkSize <= 0 {
				err = ErrStreamCorrupted
				dec.cachedError = ErrStreamCorrupted
				return
			}

			if dec.maxChunkSize > 0 && chunkSize > uint64(dec.maxChunkSize) {
				err = ErrStreamChunkTooBig
				dec.cachedError = ErrStreamChunkTooBig
				return
			}

			if sz != len(dec.dataBuffer) {
				panic("assertion filed: somehow read less bytes than buffer was")
			}

			dec.restChunkSize = int(chunkSize)
			dec.dataBuffer = dec.dataBuffer[:0]
		}

		for dec.restChunkSize > 0 {
			if len(in) == 0 {
				return
			}

			copySize := dec.restChunkSize
			if len(in) < copySize {
				copySize = len(in)
			}

			dec.dataBuffer = append(dec.dataBuffer, in[:copySize]...)
			in = in[copySize:]

			dec.restChunkSize -= copySize
		}

		if dec.restChunkSize == 0 {
			var decryptedBuffer []byte
			decryptedBuffer, err = dec.inner.Decrypt(dec.dataBuffer, dec.dataBuffer[:0])
			if err != nil {
				dec.cachedError = err
				return
			}

			dec.dataBuffer = nil

			var chunkCounterValue uint64
			var chunkCounterValueSize int

			chunkCounterValue, chunkCounterValueSize, err = dec.chunkCounterEncoding.DecodeAtStart(decryptedBuffer)
			if err != nil {
				dec.cachedError = ErrStreamCorrupted
				err = ErrStreamCorrupted
				return
			}
			decryptedBuffer = decryptedBuffer[chunkCounterValueSize:]

			if chunkCounterValue == 0 {
				// it's finalization chunk
				dec.chunkCounter = 0
			} else if chunkCounterValue != dec.chunkCounter {
				dec.cachedError = ErrStreamCorrupted
				err = ErrStreamCorrupted
				return
			} else {
				res = append(res, decryptedBuffer...)

				dec.chunkCounter += 1
			}
		}
	}
}

func (dec *cpkStreamDecryptor) Finalize() (err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	if dec.chunkCounter != 0 {
		err = ErrStreamCorrupted
		dec.cachedError = ErrStreamCorrupted
		return
	}

	err = dec.inner.Finalize()
	if err != nil {
		return
	}

	return
}
