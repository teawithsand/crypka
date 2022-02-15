package crypka

type cpkStreamEncryptor struct {
	inner Encryptor

	desiredChunkBufferSize int
	chunkBuffer            []byte

	chunkCounterEncoding intEncoding
	chunkSizeEncoding    intEncoding

	chunkCoutner uint64

	cachedError error
}

func (enc *cpkStreamEncryptor) getDataBufferView() []byte {
	return enc.chunkBuffer[enc.chunkCounterEncoding.MaxSize():]
}

func (enc *cpkStreamEncryptor) getChunkCounterBufferView() []byte {
	return enc.chunkBuffer[:enc.chunkCounterEncoding.MaxSize()]
}

func (enc *cpkStreamEncryptor) resetChunkBuffer() {
	enc.chunkBuffer = enc.chunkBuffer[:enc.chunkCounterEncoding.MaxSize()]
	for i := range enc.chunkBuffer {
		enc.chunkBuffer[i] = 0
	}
}

func (enc *cpkStreamEncryptor) extendChunkBuffer(data []byte) {
	enc.chunkBuffer = append(enc.chunkBuffer, data...)
}

func (enc *cpkStreamEncryptor) emitBuffer(appendTo []byte) (res []byte, err error) {
	chunkCounterBuffer := enc.getChunkCounterBufferView()
	chunkCounterPrefixSize := enc.chunkCounterEncoding.EncodeAtEnd(chunkCounterBuffer[:], enc.chunkCoutner)

	encBuffer := enc.chunkBuffer[len(chunkCounterBuffer)-chunkCounterPrefixSize:]

	res = appendTo
	maxChunkSizeSizeVar := enc.chunkSizeEncoding.MaxSize()

	for i := 0; i < maxChunkSizeSizeVar; i++ {
		res = append(res, 0)
	}

	chunkSizeBuffer := res[len(res)-maxChunkSizeSizeVar:]

	prevResLength := len(res)
	res, err = enc.inner.Encrypt(encBuffer, res)
	if err != nil {
		enc.cachedError = err
		return
	}
	newResLength := len(res)
	encryptedDataLength := uint64(newResLength - prevResLength)

	chunkSizePrefixSize := enc.chunkSizeEncoding.EncodeAtEnd(chunkSizeBuffer, encryptedDataLength)

	if len(chunkSizeBuffer)-chunkSizePrefixSize != 0 {
		copy(res[:], res[len(chunkSizeBuffer)-chunkSizePrefixSize:])
		res = res[:len(res)-chunkSizePrefixSize]
	}

	enc.resetChunkBuffer()
	enc.chunkCoutner += 1
	return
}

func (enc *cpkStreamEncryptor) Encrypt(in, appendTo []byte) (res []byte, err error) {
	if enc.cachedError != nil {
		err = enc.cachedError
		return
	}

	res = appendTo

	for {
		if len(in) == 0 {
			break
		}

		if len(enc.getDataBufferView()) < enc.desiredChunkBufferSize {
			appendSize := enc.desiredChunkBufferSize - len(enc.chunkBuffer)
			if len(in) < appendSize {
				appendSize = len(in)
			}
			enc.extendChunkBuffer(in[:appendSize])
			in = in[appendSize:]
		}

		if len(enc.getDataBufferView()) == enc.desiredChunkBufferSize {
			res, err = enc.emitBuffer(res)

			if err != nil {
				return
			}
		}
	}

	return
}

func (enc *cpkStreamEncryptor) Finalize(appendTo []byte) (res []byte, err error) {
	if enc.cachedError != nil {
		err = enc.cachedError
		return
	}

	// emit finalization chunk with cc value == 0
	defer func() {
		if enc.cachedError == nil {
			enc.cachedError = ErrAlreadyFinalized
		}
	}()

	if len(enc.getDataBufferView()) != 0 {
		res, err = enc.emitBuffer(appendTo)
		if err != nil {
			return
		}
	}

	totalChunks := enc.chunkCoutner

	enc.chunkCoutner = 0
	buffer := enc.getDataBufferView()
	// TODO(teawithsand): do that in less hacky way with respet to enc's extend method
	enc.chunkBuffer, _ = enc.chunkCounterEncoding.AppendToBuf(buffer, totalChunks)

	res, err = enc.emitBuffer(appendTo)
	if err != nil {
		return
	}

	// frees resources, since they are not needed after finalization
	enc.chunkBuffer = nil

	return
}
