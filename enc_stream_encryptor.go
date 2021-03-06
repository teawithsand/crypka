package crypka

func newCPKStreamEncryptor(inner Encryptor, desiredChunkBufferSize int) *cpkStreamEncryptor {
	enc := &cpkStreamEncryptor{
		inner:                  inner,
		desiredChunkBufferSize: desiredChunkBufferSize,
		chunkCoutner:           1,
	}

	enc.chunkBuffer = make([]byte, enc.chunkCounterEncoding.MaxSize())

	return enc
}

type cpkStreamEncryptor struct {
	inner Encryptor

	desiredChunkBufferSize int
	chunkBuffer            []byte

	chunkCounterEncoding    intEncoding
	chunkSizeEncoding       intEncoding
	cpkControlValueEncoding intEncoding

	chunkCoutner uint64

	cachedError error
}

func (enc *cpkStreamEncryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: true,
		EncType:              EncTypeStream,
	}
}

func (enc *cpkStreamEncryptor) resetChunkBuffer() {
	enc.chunkBuffer = enc.chunkBuffer[:enc.chunkCounterEncoding.MaxSize()]
	for i := range enc.chunkBuffer {
		enc.chunkBuffer[i] = 0
	}
}

func (enc *cpkStreamEncryptor) getDataBufferView() []byte {
	return enc.chunkBuffer[enc.chunkCounterEncoding.MaxSize():]
}

func (enc *cpkStreamEncryptor) getChunkCounterBufferView() []byte {
	return enc.chunkBuffer[:enc.chunkCounterEncoding.MaxSize()]
}

func (enc *cpkStreamEncryptor) extendChunkBuffer(data []byte) {
	enc.chunkBuffer = append(enc.chunkBuffer, data...)
}

func (enc *cpkStreamEncryptor) emitDataChunk(appendTo []byte) (res []byte, err error) {
	initialAppendToLength := len(appendTo)

	res = appendTo

	chunkCounterBuffer := enc.getChunkCounterBufferView()
	chunkCounterPrefixSize := enc.chunkCounterEncoding.EncodeAtEnd(chunkCounterBuffer[:], enc.chunkCoutner)

	encBuffer := enc.chunkBuffer[len(chunkCounterBuffer)-chunkCounterPrefixSize:]

	maxChunkSizeSizeVar := enc.chunkSizeEncoding.MaxSize()

	for i := 0; i < maxChunkSizeSizeVar; i++ {
		res = append(res, 0)
	}

	chunkSizeBufferStartIndex := len(res) - maxChunkSizeSizeVar
	chunkSizeBufferEndIndex := len(res)

	prevResLength := len(res)
	res, err = enc.inner.Encrypt(encBuffer, res)
	if err != nil {
		enc.cachedError = err
		return
	}
	newResLength := len(res)
	encryptedDataLength := uint64(newResLength - prevResLength)

	chunkSizeBuffer := res[chunkSizeBufferStartIndex:chunkSizeBufferEndIndex]

	chunkSizePrefixSize := enc.chunkSizeEncoding.EncodeAtEnd(chunkSizeBuffer, encryptedDataLength)

	memmoveBy := len(chunkSizeBuffer) - chunkSizePrefixSize
	if memmoveBy != 0 {
		moveSlice := res[initialAppendToLength:]
		copy(moveSlice[:], moveSlice[memmoveBy:])
		res = res[:len(res)-memmoveBy]
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

	for len(in) > 0 {
		if len(enc.getDataBufferView()) < enc.desiredChunkBufferSize {
			appendSize := enc.desiredChunkBufferSize - len(enc.getDataBufferView())
			if len(in) < appendSize {
				appendSize = len(in)
			}
			enc.extendChunkBuffer(in[:appendSize])
			in = in[appendSize:]
		}

		if len(enc.getDataBufferView()) == enc.desiredChunkBufferSize {
			res, err = enc.emitDataChunk(res)
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

	defer func() {
		enc.cachedError = ErrEncAlreadyFinalized
	}()

	if enc.inner.GetEncInfo().RequiresFinalization {
		panic("encryptors, which require finalization are not supported by cpkStreamEncryptor yet")
	}

	res = appendTo

	if len(enc.getDataBufferView()) > 0 {
		res, err = enc.emitDataChunk(res)
		if err != nil {
			return
		}
	}

	var sz1, sz2 int
	enc.chunkBuffer, sz2 = enc.cpkControlValueEncoding.AppendToBuf(enc.chunkBuffer, streamEndCpkControlByte.toEncodable())
	enc.chunkBuffer, sz1 = enc.chunkCounterEncoding.AppendToBuf(enc.chunkBuffer, enc.chunkCoutner)
	enc.chunkCoutner = 0

	if sz1+sz2 != len(enc.getDataBufferView()) {
		panic("assertion filed size mismatch")
	}

	res, err = enc.emitDataChunk(res)
	if err != nil {
		return
	}

	enc.chunkCoutner = 0

	return
}
