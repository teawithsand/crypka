package crypka

func newCPKStreamDecryptor(inner Decryptor, maxChunkSize int) *cpkStreamDecryptor {
	enc := &cpkStreamDecryptor{
		inner:        inner,
		maxChunkSize: maxChunkSize,
		chunkCoutner: 1,

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

	chunkCoutner uint64

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
	// // fmt.Println("DECRYPT CALL")
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	res = appendTo

	for {
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

			// fmt.Println("[decryptor]", "DDB:", dec.dataBuffer)
			// fmt.Println("[decryptor]", "found chunk of", chunkSize, "bytes", "it's size has", sz, "bytes")

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
				// // fmt.Println("accessed bytes", sz)
				// // fmt.Println("buffer size", len(dec.dataBuffer))
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
			// fmt.Println("ddb", dec.dataBuffer)
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

			if chunkCounterValue != 0 {
				// fmt.Println("[decryptor]", "final decrypted", decryptedBuffer)
				res = append(res, decryptedBuffer...)
			}
		}
	}

	return
}

func (dec *cpkStreamDecryptor) Finalize() (err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	return
}

/*


func (dec *cpkStreamDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	return

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

			if dec.maxChunkSize > 0 && chunkSize > uint64(dec.maxChunkSize) {
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
	return

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
}*/
