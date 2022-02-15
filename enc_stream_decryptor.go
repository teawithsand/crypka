package crypka

type cpkStreamDecryptor struct {
	inner Decryptor

	chunkCounterEncoding intEncoding
	chunkSizeEncoding    intEncoding
	chunkCoutner         uint64

	dataBuffer           []byte
	expectedChunkSize    int
	maxExpectedChunkSize int

	cachedError error
}
