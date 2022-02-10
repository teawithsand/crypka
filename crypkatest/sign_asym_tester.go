package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type SignAsymTester struct {
	Algo        crypka.SignAsymAlgo
	ChunkRunner *ChunkRunner

	NotMarshalable bool
}

func (tester *SignAsymTester) signAndVerifyData(signerChunks [][]byte, verifierChunks [][]byte, sk crypka.SigningKey, vk crypka.VerifyingKey) (err error) {
	if sk == nil {
		sk, _, err = tester.Algo.GenerateKeyPair(nil)
		if err != nil {
			return
		}
	}

	if vk == nil {
		_, vk, err = tester.Algo.GenerateKeyPair(nil)
		if err != nil {
			return
		}
	}

	return SignAndVerifyData(signerChunks, verifierChunks, sk, vk)
}

func (tester *SignAsymTester) Test(t *testing.T) {
	// TODO(teawithsand): implement more tests here

	chunkRunner := tester.ChunkRunner
	if chunkRunner == nil {
		chunkRunner = DefaultSignChunkRunner
	}

	t.Run("valid_sign", func(t *testing.T) {
		err := chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
			sk, vk, err := tester.Algo.GenerateKeyPair(nil)
			if err != nil {
				return
			}

			err = tester.signAndVerifyData(chunks, chunks, sk, vk)
			return
		})
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("invalid_sign", func(t *testing.T) {
		t.Run("when_data_mismatch", func(t *testing.T) {
			err := chunkRunner.runWithDifferentChunks(func(lhs, rhs [][]byte) (err error) {
				sk, vk, err := tester.Algo.GenerateKeyPair(nil)
				if err != nil {
					return
				}

				err = tester.signAndVerifyData(lhs, rhs, sk, vk)
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

		t.Run("when_key_mismatch", func(t *testing.T) {
			err := chunkRunner.runWithDifferentChunks(func(lhs, rhs [][]byte) (err error) {
				err = tester.signAndVerifyData(lhs, rhs, nil, nil)
				if err == nil {
					err = errors.New("no error when key mismatch")
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
	})

	if !tester.NotMarshalable {
		t.Run("can_marshal_signing_key", func(t *testing.T) {
			sk, vk, err := tester.Algo.GenerateKeyPair(nil)
			if err != nil {
				t.Error(err)
				return
			}
			buf, err := crypka.MarshalKeyToSlice(sk)
			if err != nil {
				t.Error(err)
				return
			}

			parsedSk, err := tester.Algo.ParseSigningKey(nil, buf)
			if err != nil {
				t.Error(err)
				return
			}

			err = chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
				err = tester.signAndVerifyData(chunks, chunks, parsedSk, vk)
				return
			})

			if err != nil {
				t.Error(err)
			}
		})

		t.Run("can_marshal_verifying_key", func(t *testing.T) {
			sk, vk, err := tester.Algo.GenerateKeyPair(nil)
			if err != nil {
				t.Error(err)
				return
			}
			buf, err := crypka.MarshalKeyToSlice(vk)
			if err != nil {
				t.Error(err)
				return
			}

			parsedVk, err := tester.Algo.ParseVerifyingKey(nil, buf)
			if err != nil {
				t.Error(err)
				return
			}

			err = chunkRunner.RunWithSameChunks(func(chunks [][]byte) (err error) {
				err = tester.signAndVerifyData(chunks, chunks, sk, parsedVk)
				return
			})

			if err != nil {
				t.Error(err)
			}
		})
	}
}

func (tester SignAsymTester) Benchmark(b *testing.B) {
	panic("NIY")
}

// TODO(teawithsand): when go 1.18 will be released, add fuzz functions here
