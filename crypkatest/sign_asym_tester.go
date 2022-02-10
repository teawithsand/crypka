package crypkatest

import (
	"errors"
	"io"
	"testing"

	"github.com/teawithsand/crypka"
)

type SignAsymTester struct {
	Algo crypka.SignAsymAlgo
	RNG  io.Reader

	NotMarshalable bool
}

func (tester *SignAsymTester) Test(t *testing.T) {

	signChunksWithDifferentKeys := func(
		signerChunks [][]byte,
		verifierChunks [][]byte,
		sk crypka.SigningKey,
		vk crypka.VerifyingKey,
	) (err error) {
		if sk == nil {
			sk, _, err = tester.Algo.GenerateKeyPair(nil)
			if err != nil {
				t.Error(err)
				return
			}
		}

		if vk == nil {
			_, vk, err = tester.Algo.GenerateKeyPair(nil)
			if err != nil {
				t.Error(err)
				return
			}
		}

		signer, err := sk.MakeSigner(nil)
		if err != nil {
			t.Error(err)
		}

		verifier, err := vk.MakeVerifier(nil)
		if err != nil {
			t.Error(err)
		}

		for _, data := range signerChunks {
			_, err = signer.Write(data)
			if err != nil {
				return
			}
		}

		sign, err := signer.Finalize(nil)
		if err != nil {
			return
		}

		for _, data := range verifierChunks {
			_, err = verifier.Write(data)
			if err != nil {
				return
			}
		}

		err = verifier.Verify(sign)
		return
	}

	signChunksWithSameKey := func(signerChunks [][]byte, verifierChunks [][]byte) (err error) {
		sk, vk, err := tester.Algo.GenerateKeyPair(nil)
		if err != nil {
			t.Error(err)
			return
		}
		return signChunksWithDifferentKeys(signerChunks, verifierChunks, sk, vk)
	}

	runWithSameChunks := func(t *testing.T, receiver func(buffers [][]byte) (err error)) {
		for _, sz := range signTestChunkSizes {
			buffers := RNGReadBuffers(tester.RNG, sz)
			err := receiver(buffers)

			if err != nil {
				t.Error(err)
				return
			}
		}
	}

	runWithDifferentChunks := func(t *testing.T, receiver func(lhsBuffers, rhsBuffers [][]byte) (err error)) {
		for _, sz := range signTestChunkSizes {
			lhsBuffers := RNGReadBuffers(tester.RNG, sz)
			rhsBuffers := RNGReadBuffers(tester.RNG, sz)

			if BuffersEqual(lhsBuffers, rhsBuffers) {
				continue
			}

			err := receiver(lhsBuffers, rhsBuffers)
			if err != nil {
				t.Error(err)
				return
			}
		}
	}

	// TODO(teawithsand): implement more tests here

	t.Run("valid_sign", func(t *testing.T) {
		runWithSameChunks(t, func(chunks [][]byte) (err error) {
			err = signChunksWithSameKey(chunks, chunks)
			return
		})
	})

	t.Run("invalid_sign", func(t *testing.T) {
		t.Run("when_data_mismatch", func(t *testing.T) {
			runWithDifferentChunks(t, func(lhs, rhs [][]byte) (err error) {
				err = signChunksWithSameKey(lhs, rhs)
				if err == nil {
					err = errors.New("no error when data mismatch")
				}
				if errors.Is(err, crypka.ErrInvalidSign) {
					err = nil
				}
				return
			})
		})

		t.Run("when_key_mismatch", func(t *testing.T) {
			runWithSameChunks(t, func(chunks [][]byte) (err error) {
				err = signChunksWithDifferentKeys(chunks, chunks, nil, nil)
				if err == nil {
					err = errors.New("no error when key mistmatch")
				}
				if errors.Is(err, crypka.ErrInvalidSign) {
					err = nil
				}
				return
			})
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

			runWithSameChunks(t, func(buffers [][]byte) (err error) {
				return signChunksWithDifferentKeys(buffers, buffers, parsedSk, vk)
			})
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

			runWithSameChunks(t, func(buffers [][]byte) (err error) {
				return signChunksWithDifferentKeys(buffers, buffers, sk, parsedVk)
			})
		})
	}
}

func (tester SignAsymTester) Benchmark(b *testing.B) {
	panic("NIY")
}

// TODO(teawithsand): when go 1.18 will be released, add fuzz functions here
