package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type SignSymmTester struct {
	Algo crypka.SignSymmAlgo
	TestScopeUtil

	NotMarshalable bool
}

func (tester *SignSymmTester) init() {
	if tester.TestScopeUtil.ChunkRunnerConfig.IsEmpty() {
		tester.TestScopeUtil.ChunkRunnerConfig = DefaultSignChunkRunnerConfig
	}
}

func (tester *SignSymmTester) signAndVerifyData(signerChunks [][]byte, verifierChunks [][]byte, bag SignKeyBag) (err error) {
	err = bag.EnsureValidSymm(tester.Algo)
	if err != nil {
		return
	}

	return SignAndVerifyData(signerChunks, verifierChunks, bag)
}

func (tester *SignSymmTester) Test(t *testing.T) {
	tester.init()

	// TODO(teawithsand): implement more tests here

	t.Run("valid_sign", func(t *testing.T) {
		scope := tester.TestScopeUtil.GetTestScope()

		err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
			key, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
			if err != nil {
				return
			}

			err = tester.signAndVerifyData(chunks, chunks, SignKeyBag{
				SignKey: key,
				VerKey:  key,
			})
			return
		})

		if err != nil {
			t.Error(err)
		}
	})

	t.Run("invalid_sign", func(t *testing.T) {
		t.Run("when_data_mismatch", func(t *testing.T) {
			scope := tester.TestScopeUtil.GetTestScope()

			err := scope.GetChunkRunner().runWithDifferentChunks(func(lhs, rhs [][]byte) (err error) {
				key, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
				if err != nil {
					return
				}

				err = tester.signAndVerifyData(lhs, rhs, SignKeyBag{
					SignKey: key,
					VerKey:  key,
				})
				if err == nil {
					err = errors.New("no error when data mismatch")
				}
				if errors.Is(err, crypka.ErrSignInvalid) {
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
				scope := tester.TestScopeUtil.GetTestScope()

				scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.signAndVerifyData(chunks, chunks, SignKeyBag{
						BaseBag: scope.GetBaseBag(),
					})
					if err == nil {
						err = errors.New("no error when key mismatch")
					}
					if errors.Is(err, crypka.ErrSignInvalid) {
						err = nil
					}
					return
				})
			})
		}
	})

	if !tester.NotMarshalable {
		t.Run("can_marshal_symm_signing_key", func(t *testing.T) {
			scope := tester.TestScopeUtil.GetTestScope()

			key, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
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

			err = scope.GetChunkRunner().RunWithSameChunks(func(buffers [][]byte) (err error) {
				err = tester.signAndVerifyData(buffers, buffers, SignKeyBag{
					SignKey: key,
					VerKey:  parsedKey,
				})
				if err != nil {
					return
				}

				err = tester.signAndVerifyData(buffers, buffers, SignKeyBag{
					SignKey: parsedKey,
					VerKey:  key,
				})
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
