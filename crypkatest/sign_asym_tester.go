package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type SignAsymTester struct {
	Algo crypka.SignAsymAlgo
	TestScopeUtil

	NotMarshalable bool
}

func (tester *SignAsymTester) init() {
	if tester.TestScopeUtil.ChunkRunnerConfig.IsEmpty() {
		tester.TestScopeUtil.ChunkRunnerConfig = DefaultSignChunkRunnerConfig
	}
}

func (tester *SignAsymTester) signAndVerifyData(signerChunks [][]byte, verifierChunks [][]byte, bag SignKeyBag) (err error) {
	err = bag.EnsureValidAsym(tester.Algo)
	if err != nil {
		return
	}
	return SignAndVerifyData(signerChunks, verifierChunks, bag)
}

func (tester *SignAsymTester) Test(t *testing.T) {
	tester.init()

	// TODO(teawithsand): implement more tests here

	t.Run("valid_sign", func(t *testing.T) {
		scope := tester.TestScopeUtil.GetTestScope()

		err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
			sk, vk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
			if err != nil {
				return
			}

			err = tester.signAndVerifyData(chunks, chunks, SignKeyBag{
				SignKey: sk,
				VerKey:  vk,
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
				sk, vk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
				if err != nil {
					return
				}

				err = tester.signAndVerifyData(lhs, rhs, SignKeyBag{
					SignKey: sk,
					VerKey:  vk,
				})
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
			scope := tester.TestScopeUtil.GetTestScope()

			err := scope.GetChunkRunner().runWithDifferentChunks(func(lhs, rhs [][]byte) (err error) {
				err = tester.signAndVerifyData(lhs, rhs, SignKeyBag{BaseBag: scope.GetBaseBag()})
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
			scope := tester.TestScopeUtil.GetTestScope()

			sk, vk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
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

			err = scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
				err = tester.signAndVerifyData(chunks, chunks, SignKeyBag{
					SignKey: parsedSk,
					VerKey:  vk,
				})
				return
			})

			if err != nil {
				t.Error(err)
			}
		})

		t.Run("can_marshal_verifying_key", func(t *testing.T) {
			scope := tester.TestScopeUtil.GetTestScope()

			sk, vk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
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

			err = scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
				err = tester.signAndVerifyData(chunks, chunks, SignKeyBag{
					SignKey: sk,
					VerKey:  parsedVk,
				})
				return
			})

			if err != nil {
				t.Error(err)
			}
		})
	}
}

func (tester SignAsymTester) Benchmark(b *testing.B) {
	tester.init()

	panic("NIY")
}

// TODO(teawithsand): when go 1.18 will be released, add fuzz functions here
