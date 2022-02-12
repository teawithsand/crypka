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

func (tester *EncSymmTester) encryptAndDecryptStreamData(chunks [][]byte, rdSizes []int, ek crypka.EncKey, dk crypka.DecKey) (err error) {
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
	return EncryptAndDecryptStreamData(chunks, rdSizes, ek, dk)
}

func (tester *EncSymmTester) encryptAndDecryptChainData(chunks [][]byte, ek crypka.EncKey, dk crypka.DecKey) (err error) {
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
	return EncryptAndDecryptChainData(chunks, ek, dk)
}

func (tester *EncSymmTester) Test(t *testing.T) {
	chunkRunner := tester.ChunkRunner
	if chunkRunner == nil {
		chunkRunner = DefaultEncChunkRunner
	}

	if tester.Algo.GetInfo().EncType == crypka.EncTypeStream {
		t.Run("enc_stream", func(t *testing.T) {
			t.Run("valid_encryption", func(t *testing.T) {
				err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
					ek, err := tester.Algo.GenerateKey(nil)
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptStreamData(chunks, nil, ek, ek)
					return
				})
				if err != nil {
					t.Error(err)
				}
			})

			t.Run("invalid_when_key_mistmatch", func(t *testing.T) {
				err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.encryptAndDecryptStreamData(chunks, nil, nil, nil)
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
		})
	}

	{
		t.Run("enc_chain", func(t *testing.T) {
			t.Run("valid_encryption", func(t *testing.T) {
				err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
					ek, err := tester.Algo.GenerateKey(nil)
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptChainData(chunks, ek, ek)
					return
				})
				if err != nil {
					t.Error(err)
				}
			})

			t.Run("invalid_when_key_mistmatch", func(t *testing.T) {
				err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.encryptAndDecryptChainData(chunks, nil, nil)
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
		})
	}

	if !tester.NotMarshalable {
		t.Run("can_marshal_symm_signing_key__chain_test", func(t *testing.T) {
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
				err = tester.encryptAndDecryptChainData(chunks, originalKey, parsedKey)
				if err != nil {
					return
				}
				err = tester.encryptAndDecryptChainData(chunks, parsedKey, originalKey)
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
