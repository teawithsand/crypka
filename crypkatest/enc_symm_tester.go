package crypkatest

import (
	"errors"
	"testing"

	"github.com/teawithsand/crypka"
)

type EncSymmTester struct {
	Algo crypka.EncSymmAlgo
	TestScopeUtil

	NotMarshalable bool
	IsBlank        bool
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

func (tester *EncSymmTester) init() {
	if tester.TestScopeUtil.ChunkRunnerConfig.IsEmpty() {
		tester.TestScopeUtil.ChunkRunnerConfig = DefaultEncChunkRunnerConfig
	}
}

func (tester *EncSymmTester) encryptAndDecryptStreamData(
	chunks [][]byte,
	rdSizes []int,
	bag EncKeyBag,
) (err error) {
	err = bag.EnsureValidSymm(tester.Algo)
	if err != nil {
		return
	}
	return EncryptAndDecryptStreamData(chunks, rdSizes, bag)
}

func (tester *EncSymmTester) encryptAndDecryptChainData(chunks [][]byte, bag EncKeyBag) (err error) {
	err = bag.EnsureValidSymm(tester.Algo)
	if err != nil {
		return
	}
	return EncryptAndDecryptChainData(chunks, bag)
}

func (tester *EncSymmTester) Test(t *testing.T) {
	tester.init()

	if tester.Algo.GetInfo().EncType == crypka.EncTypeStream {
		t.Run("enc_stream", func(t *testing.T) {
			t.Run("valid_encryption", func(t *testing.T) {
				scope := tester.TestScopeUtil.GetTestScope()

				err := scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					ek, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptStreamData(chunks, nil, EncKeyBag{
						EncKey: ek,
						DecKey: ek,
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
					ek, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
					if err != nil {
						return
					}

					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						EncKey: ek,
						DecKey: ek,
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

				originalKey, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
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

				err = scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						EncKey: originalKey,
						DecKey: parsedKey,
					})
					if err != nil {
						return
					}
					err = tester.encryptAndDecryptChainData(chunks, EncKeyBag{
						EncKey: parsedKey,
						DecKey: originalKey,
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
				scope := tester.TestScopeUtil.GetTestScope()

				originalKey, err := tester.Algo.GenerateKey(nil, scope.GetRNG())
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

				err = scope.GetChunkRunner().RunWithSameChunks(func(chunks [][]byte) (err error) {
					err = tester.encryptAndDecryptStreamData(chunks, nil, EncKeyBag{
						EncKey: originalKey,
						DecKey: parsedKey,
					})
					if err != nil {
						return
					}
					err = tester.encryptAndDecryptStreamData(chunks, nil, EncKeyBag{
						EncKey: parsedKey,
						DecKey: originalKey,
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
}
