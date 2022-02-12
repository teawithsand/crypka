package crypkatest

import (
	"bytes"
	"errors"
	"io"

	"github.com/teawithsand/crypka"
)

var ErrTestingEncrpytedDecryptedMismatch = errors.New("crypka/crypkatest: encrypted and decrpyted data mismatch")

func EncryptAndDecryptStreamData(chunks [][]byte, rdSizes []int, ek crypka.EncKey, dk crypka.DecKey) (err error) {
	enc, err := ek.MakeEncryptor(nil)
	if err != nil {
		return
	}
	dec, err := dk.MakeDecryptor(nil)
	if err != nil {
		return
	}

	var continousInput []byte
	for _, chunk := range chunks {
		continousInput = append(continousInput, chunk...)
	}

	var encRes []byte
	for _, chunk := range chunks {
		encRes, err = enc.Encrypt(chunk, encRes)
		if err != nil {
			return
		}
	}

	encRes, err = enc.Finalize(encRes)
	if err != nil {
		return
	}

	if len(rdSizes) == 0 {
		for _, chunk := range chunks {
			rdSizes = append(rdSizes, len(chunk))
		}
	}

	rd := bytes.NewReader(encRes)

	var decRes []byte
	for _, sz := range rdSizes {
		buf := make([]byte, sz)
		_, err = io.ReadFull(rd, buf)
		if err != nil {
			return
		}
		decRes, err = dec.Decrypt(buf, decRes)
		if err != nil {
			return
		}
	}

	if rd.Len() > 0 {
		buf := make([]byte, rd.Len())
		_, err = io.ReadFull(rd, buf)
		if err != nil {
			return
		}
		decRes, err = dec.Decrypt(buf, decRes)
		if err != nil {
			return
		}
	}

	err = dec.Finalize()
	if err != nil {
		return
	}

	if !bytes.Equal(continousInput, decRes) {
		err = ErrTestingEncrpytedDecryptedMismatch
		return
	}

	return
}

func EncryptAndDecryptChainData(chunks [][]byte, ek crypka.EncKey, dk crypka.DecKey) (err error) {
	enc, err := ek.MakeEncryptor(nil)
	if err != nil {
		return
	}
	dec, err := dk.MakeDecryptor(nil)
	if err != nil {
		return
	}

	for _, chunk := range chunks {
		var encryptedChunk []byte
		var decryptedChunk []byte

		encryptedChunk, err = enc.Encrypt(chunk, nil)
		if err != nil {
			return
		}

		decryptedChunk, err = dec.Decrypt(encryptedChunk, nil)
		if err != nil {
			return
		}

		if !bytes.Equal(chunk, decryptedChunk) {
			err = ErrTestingEncrpytedDecryptedMismatch
			return
		}
	}

	return
}

// TODO(teawithsand): fuzz test for block decryptor being able to decrypt block at random
