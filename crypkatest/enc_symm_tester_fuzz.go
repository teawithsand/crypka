package crypkatest

import (
	"bytes"
	"errors"
	"testing"
)

func (tester EncSymmTester) Fuzz(f *testing.F, method EncSymmFuzzMethod) {
	tester.init()

	esk, err := tester.Algo.GenerateKey(nil, nil)
	if err != nil {
		f.Error(err)
		return
	}

	if method == EncSymmFuzzDecryptorChunks {
		f.Fuzz(func(t *testing.T, data []byte) {
			dec, err := esk.MakeDecryptor(nil)
			if err != nil {
				t.Error(err)
				return
			}

			FuzzingChunks(data, func(buf []byte) (err error) {
				dec.Decrypt(buf, nil)
				return
			})

			dec.Finalize()
		})
	} else if method == EncSymmFuzzEncryptorChunks {
		f.Fuzz(func(t *testing.T, data []byte) {
			enc, err := esk.MakeEncryptor(nil)
			if err != nil {
				t.Error(err)
				return
			}

			err = FuzzingChunks(data, func(buf []byte) (err error) {
				_, err = enc.Encrypt(buf, nil)
				return
			})
			if err != nil {
				t.Error(err)
				return
			}

			_, err = enc.Finalize(nil)
			if err != nil {
				t.Error(err)
				return
			}
		})
	} else if method == EncSymmFuzzEncryptDecryptChunks {
		// TODO(teawithsand): make this test work differently for different algorithm kinds
		f.Fuzz(func(t *testing.T, data []byte) {
			enc, err := esk.MakeEncryptor(nil)
			if err != nil {
				t.Error(err)
				return
			}

			var encrypted []byte
			var input []byte

			err = FuzzingChunks(data, func(buf []byte) (err error) {
				input = append(input, buf...)
				encrypted, err = enc.Encrypt(buf, encrypted)
				return
			})
			if err != nil {
				t.Error(err)
				return
			}

			encrypted, err = enc.Finalize(encrypted)
			if err != nil {
				t.Error(err)
				return
			}

			dec, err := esk.MakeDecryptor(nil)
			if err != nil {
				t.Error(err)
				return
			}

			// TODO(teawithsand): randomize decryption chunk size

			var decrypted []byte
			decrypted, err = dec.Decrypt(encrypted, decrypted)
			if err != nil {
				t.Error(err)
				return
			}

			err = dec.Finalize()
			if err != nil {
				t.Error(err)
				return
			}

			if !bytes.Equal(decrypted, input) {
				t.Error(errors.New("I/O data mistmatch"))
				return
			}

			return
		})
	} else {
		panic("Unknown method")
	}
}
