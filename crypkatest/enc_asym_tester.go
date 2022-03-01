package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type EncAsymFuzzMethod int

const (
	EncAsymFuzzEncryptorChunks      EncAsymFuzzMethod = 1
	EncAsymFuzzDecryptorChunks      EncAsymFuzzMethod = 2
	EncAsymFuzzEncryptDecryptChunks EncAsymFuzzMethod = 3
)

type EncAsymTester struct {
	Algo crypka.EncAsymAlgo
	TestScopeUtil

	NotMarshalable bool
	IsBlank        bool
}

func (tester *EncAsymTester) init() {
	if tester.TestScopeUtil.ChunkRunnerConfig.IsEmpty() {
		tester.TestScopeUtil.ChunkRunnerConfig = DefaultEncChunkRunnerConfig
	}
}

func (tester *EncAsymTester) encryptAndDecryptStreamData(
	chunks [][]byte,
	rdSizes []int,
	bag EncKeyBag,
) (err error) {
	err = bag.EnsureValidAsym(tester.Algo)
	if err != nil {
		return
	}
	return EncryptAndDecryptStreamData(chunks, rdSizes, bag)
}

func (tester *EncAsymTester) encryptAndDecryptChainData(chunks [][]byte, bag EncKeyBag) (err error) {
	err = bag.EnsureValidAsym(tester.Algo)
	if err != nil {
		return
	}
	return EncryptAndDecryptChainData(chunks, bag)
}

func (tester *EncAsymTester) Test(t *testing.T) {
	tester.init()

	if tester.Algo.GetInfo().EncType == crypka.EncTypeStream {
		t.Run("enc_stream", func(t *testing.T) {
			t.Run("valid_encryption", func(t *testing.T) {
				scope := tester.TestScopeUtil.GetTestScope()

				err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					ek, dk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptStreamData(chunks, nil, EncKeyBag{
						EncKey: ek,
						DecKey: dk,
					})
					return
				})
				if err != nil {
					t.Error(err)
				}
			})

			if !tester.IsBlank {
				t.Run("invalid_when_key_mistmatch", func(t *testing.T) {
					scope := tester.TestScopeUtil.GetTestScope()

					err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
						err = tester.encryptAndDecryptStreamData(chunks, nil, EncKeyBag{
							BaseBag: scope.GetBaseBag(),
						})
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
			}
		})
	}

	if tester.Algo.GetInfo().EncType == crypka.EncTypeChain {
		t.Run("enc_chain", func(t *testing.T) {
			t.Run("valid_encryption", func(t *testing.T) {
				scope := tester.TestScopeUtil.GetTestScope()

				err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					ek, dk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						EncKey: ek,
						DecKey: dk,
					})
					return
				})
				if err != nil {
					t.Error(err)
				}
			})

			t.Run("invalid_when_key_mistmatch", func(t *testing.T) {
				scope := tester.TestScopeUtil.GetTestScope()

				err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						BaseBag: scope.GetBaseBag(),
					})
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
		if tester.Algo.GetInfo().EncType == crypka.EncTypeChain || tester.Algo.GetInfo().EncType == crypka.EncTypeBlock {
			t.Run("can_marshal_symm_signing_key__chain_test", func(t *testing.T) {
				scope := tester.TestScopeUtil.GetTestScope()

				originalEk, originalDk, err := tester.Algo.GenerateKeyPair(nil, scope.GetRNG())
				if err != nil {
					t.Error(err)
					return
				}

				buf, err := crypka.MarshalKeyToSlice(originalEk)
				if err != nil {
					t.Error(err)
					return
				}

				parsedEk, err := tester.Algo.ParseEncKey(nil, buf)
				if err != nil {
					t.Error(err)
					return
				}

				buf, err = crypka.MarshalKeyToSlice(originalDk)
				if err != nil {
					t.Error(err)
					return
				}

				parsedDk, err := tester.Algo.ParseDecKey(nil, buf)
				if err != nil {
					t.Error(err)
					return
				}

				err = scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						EncKey: originalEk,
						DecKey: parsedDk,
					})
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						EncKey: parsedEk,
						DecKey: originalDk,
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
		} else {
			t.Run("can_marshal_symm_signing_key__stream_test", func(t *testing.T) {
				t.Error("NIY")
			})
		}
	}
}
