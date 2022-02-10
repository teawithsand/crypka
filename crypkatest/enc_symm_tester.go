package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type EncSymmTester struct {
	Algo        crypka.EncSymmAlgo
	ChunkRunner *ChunkRunner

	NotMarshalable bool
}

/*
	if ek == nil {
		ek, err = algo.GenerateKey(nil)
		if err != nil {
			return
		}
	}
	if dk == nil {
		dk, err = algo.GenerateKey(nil)
		if err != nil {
			return
		}
	}
*/

func (tester *EncSymmTester) encryptAndDecryptData(chunks [][]byte, rdSizes []int, ek crypka.EncKey, dk crypka.DecKey) (err error) {
	if ek == nil {
		ek, err = tester.Algo.GenerateKey(nil)
		if err != nil {
			return
		}
	}
	if dk == nil {
		dk, err = tester.Algo.GenerateKey(nil)
		if err != nil {
			return
		}
	}
	return EncryptAndDecryptData(chunks, rdSizes, ek, dk)
}

func (tester *EncSymmTester) Test(t *testing.T) {
	chunkRunner := tester.ChunkRunner
	if chunkRunner == nil {
		chunkRunner = DefaultEncChunkRunner
	}

	t.Run("valid_encryption", func(t *testing.T) {
		err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
			ek, err := tester.Algo.GenerateKey(nil)
			if err != nil {
				return
			}

			err = tester.encryptAndDecryptData(chunks, nil, ek, ek)
			return
		})
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("invalid_when_key_mistmatch", func(t *testing.T) {
		err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
			err = tester.encryptAndDecryptData(chunks, nil, nil, nil)
			return
		})

		if err == nil {
			err = errors.New("expected decryption to fail since keys are invalid")
		} else {
			err = nil
		}

		if err != nil {
			t.Error(err)
		}
	})

	if !tester.NotMarshalable {
		t.Run("can_marshal_symm_signing_key", func(t *testing.T) {
			originalKey, err := tester.Algo.GenerateKey(nil)
			if err != nil {
				t.Error(err)
				return
			}
			buf, err := crypka.MarshalKeyToSlice(originalKey)
			if err != nil {
				t.Error(err)
				return
			}

			parsedKey, err := tester.Algo.ParseSymmEncKey(nil, buf)
			if err != nil {
				t.Error(err)
				return
			}

			err = chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
				err = tester.encryptAndDecryptData(chunks, nil, originalKey, parsedKey)
				if err != nil {
					return
				}
				err = tester.encryptAndDecryptData(chunks, nil, parsedKey, originalKey)
				if err != nil {
					return
				}
				return
			})
			if err != nil {
				t.Error(err)
				return
			}
		})
	}
}
