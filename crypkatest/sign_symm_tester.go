package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type SignSymmTester struct {
	Algo        crypka.SignSymmAlgo
	ChunkRunner *ChunkRunner

	NotMarshalable bool
}

func (tester *SignSymmTester) signAndVerifyData(signerChunks [][]byte, verifierChunks [][]byte, sk crypka.SigningKey, vk crypka.VerifyingKey) (err error) {
	if sk == nil {
		sk, err = tester.Algo.GenerateKey(nil)
		if err != nil {
			return
		}
	}

	if vk == nil {
		vk, err = tester.Algo.GenerateKey(nil)
		if err != nil {
			return
		}
	}

	return SignAndVerifyData(signerChunks, verifierChunks, sk, vk)
}

func (tester *SignSymmTester) Test(t *testing.T) {
	// TODO(teawithsand): implement more tests here

	chunkRunner := tester.ChunkRunner
	if chunkRunner == nil {
		chunkRunner = DefaultSignChunkRunner
	}

	t.Run("valid_sign", func(t *testing.T) {
		err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
			key, err := tester.Algo.GenerateKey(nil)
			if err != nil {
				return
			}

			err = tester.signAndVerifyData(chunks, chunks, key, key)
			return
		})

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("invalid_sign", func(t *testing.T) {
		t.Run("when_data_mismatch", func(t *testing.T) {
			err := chunkRunner.runWithDifferentChunks(func(lhs, rhs [][]byte) (err error) {
				key, err := tester.Algo.GenerateKey(nil)
				if err != nil {
					return
				}

				err = tester.signAndVerifyData(lhs, rhs, key, key)
				if err == nil {
					err = errors.New("no error when data mismatch")
				}
				if errors.Is(err, crypka.ErrInvalidSign) {
					err = nil
				}
				return
			})

			if err != nil {
				t.Error(err)
			}
		})

		if tester.Algo.GetInfo().Type != crypka.HashAlgorithmType {
			t.Run("when_key_mistmatch", func(t *testing.T) {
				chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.signAndVerifyData(chunks, chunks, nil, nil)
					if err == nil {
						err = errors.New("no error when key mismatch")
					}
					if errors.Is(err, crypka.ErrInvalidSign) {
						err = nil
					}
					return
				})
			})
		}
	})

	if !tester.NotMarshalable {
		t.Run("can_marshal_symm_signing_key", func(t *testing.T) {
			key, err := tester.Algo.GenerateKey(nil)
			if err != nil {
				t.Error(err)
				return
			}
			buf, err := crypka.MarshalKeyToSlice(key)
			if err != nil {
				t.Error(err)
				return
			}

			parsedKey, err := tester.Algo.ParseSymmSignKey(nil, buf)
			if err != nil {
				t.Error(err)
				return
			}

			err = chunkRunner.RunWithSameChunks(func(buffers [][]byte) (err error) {
				err = tester.signAndVerifyData(buffers, buffers, key, parsedKey)
				if err != nil {
					return
				}

				err = tester.signAndVerifyData(buffers, buffers, parsedKey, key)
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

func (tester SignSymmTester) Benchmark(b *testing.B) {
	panic("NIY")
}

// TODO(teawithsand): when go 1.18 will be released, add fuzz functions here
