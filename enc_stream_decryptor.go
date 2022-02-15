package crypka

type cpkStreamDecryptor struct {
	inner Decryptor

	maxExpectedChunkSize int

	chunkCounterEncoding intEncoding
	chunkSizeEncoding    intEncoding

	chunkCoutner uint64

	dataBuffer    []byte
	restChunkSize int

	cachedError error
}

func (dec *cpkStreamDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	if dec.chunkCoutner == 0 {
		err = ErrStreamCorrupted
		dec.cachedError = ErrStreamCorrupted
		return
	}

	yieldedSomeData := false
	defer func() {
		// unset error in such case, and set cached one
		if yieldedSomeData {
			err = nil
			dec.cachedError = err
		}
	}()

	doneSomething := true
	for {
		if !doneSomething {
			return
		}
		doneSomething = false

		if dec.restChunkSize == 0 {
			// reading size rather than chunk
			var chunkSize uint64
			var sz int

			chunkSize, sz, err = dec.chunkSizeEncoding.DecodeAtStart(dec.dataBuffer)
			if err != nil {
				if len(dec.dataBuffer) >= dec.chunkSizeEncoding.MaxSize() {
					dec.cachedError = err
					return
				}
				dec.dataBuffer = append(dec.dataBuffer, in[0])
				in = in[1:]

				doneSomething = true
				continue
			}

			if dec.maxExpectedChunkSize > 0 && chunkSize > uint64(dec.maxExpectedChunkSize) {
				err = ErrStreamChunkTooBig
				return
			}

			dec.restChunkSize = int(chunkSize)
			dec.dataBuffer = dec.dataBuffer[sz:]

			doneSomething = true
			continue
		}

		if len(dec.dataBuffer) < dec.restChunkSize {
			copySize := dec.restChunkSize
			if len(in) < copySize {
				copySize = len(in)
			}

			dec.dataBuffer = append(dec.dataBuffer, in[:copySize]...)
			in = in[copySize:]
		}

		if len(dec.dataBuffer) < dec.restChunkSize {
			return
		}

		var decryptedData []byte
		decryptedData, err = dec.inner.Decrypt(dec.dataBuffer, dec.dataBuffer[:0])
		if err != nil {
			dec.cachedError = err
			return
		}

		var chunkCounterValue uint64
		var chunkCounterValueSize int
		chunkCounterValue, chunkCounterValueSize, err = dec.chunkCounterEncoding.DecodeAtStart(decryptedData)
		if err != nil {
			dec.cachedError = err
			return
		}

		decryptedData = decryptedData[chunkCounterValueSize:]

		if chunkCounterValue == 0 {
			var finalChunkCounter uint64
			var finalChunkCounterSize int

			finalChunkCounter, finalChunkCounterSize, err = dec.chunkCounterEncoding.DecodeAtStart(decryptedData)
			if err != nil {
				dec.cachedError = err
				return
			}

			if finalChunkCounter != dec.chunkCoutner {
				err = ErrStreamCorrupted
				dec.cachedError = ErrStreamCorrupted
				return
			}

			dec.chunkCoutner = 0
			decryptedData = decryptedData[finalChunkCounterSize:]

			if len(decryptedData) != 0 {
				err = ErrStreamCorrupted
				return
			}
		}

		if dec.chunkCoutner != chunkCounterValue {
			err = ErrStreamCorrupted
			dec.cachedError = err

			return
		}

		res = append(res, decryptedData...)

		dec.dataBuffer = dec.dataBuffer[:0]

		doneSomething = true
		yieldedSomeData = true
	}
}

func (dec *cpkStreamDecryptor) Finalize() (err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}
	defer func() {
		dec.cachedError = ErrStreamCorrupted
	}()

	if dec.chunkCoutner != 0 {
		err = ErrStreamCorrupted
		return
	}

	return
}
