package crypkatest

import (
	"errors"
	"io"
	"testing"

	"github.com/teawithsand/crypka"
)

type SignSymmTester struct {
	Algo           crypka.SignSymmAlgo
	RNG            io.Reader
	NotMarshalable bool
}

func (tester *SignSymmTester) Test(t *testing.T) {

	signChunksWithDifferentKeys := func(
		signerChunks [][]byte,
		verifierChunks [][]byte,
		sk crypka.SigningKey,
		vk crypka.VerifyingKey,
	) (err error) {
		if sk == nil {
			sk, err = tester.Algo.GenerateKey(nil)
			if err != nil {
				t.Error(err)
				return
			}
		}

		if vk == nil {
			vk, err = tester.Algo.GenerateKey(nil)
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
		key, err := tester.Algo.GenerateKey(nil)
		if err != nil {
			t.Error(err)
			return
		}
		return signChunksWithDifferentKeys(signerChunks, verifierChunks, key, key)
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

		if tester.Algo.GetInfo().Type != crypka.HashAlgorithmType {
			t.Run("when_key_mistmatch", func(t *testing.T) {
				runWithSameChunks(t, func(chunks [][]byte) (err error) {
					err = signChunksWithDifferentKeys(chunks, chunks, nil, nil)
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

			runWithSameChunks(t, func(buffers [][]byte) (err error) {
				return signChunksWithDifferentKeys(buffers, buffers, parsedKey, key)
			})
		})
	}
}

func (tester SignSymmTester) Benchmark(b *testing.B) {
	panic("NIY")
}

// TODO(teawithsand): when go 1.18 will be released, add fuzz functions here
