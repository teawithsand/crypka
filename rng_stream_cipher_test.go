package crypka_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestRNG_Cipher_WithAES128CTR(t *testing.T) {
	t.Run("without_rekeing", func(t *testing.T) {
		tester := crypkatest.RNGTester{
			Algo: &crypka.EncStreamRNGAlgo{
				CipherFactory: func(key []byte) (res cipher.Stream, err error) {
					block, err := aes.NewCipher(key)
					if err != nil {
						return
					}
					iv := make([]byte, len(key))
					res = cipher.NewCTR(block, iv)
					return
				},

				KeyLength: 16,
			},
		}

		tester.Test(t)
	})

	t.Run("with_rekeing", func(t *testing.T) {
		tester := crypkatest.RNGTester{
			Algo: &crypka.EncStreamRNGAlgo{
				CipherFactory: func(key []byte) (res cipher.Stream, err error) {
					block, err := aes.NewCipher(key)
					if err != nil {
						return
					}
					iv := make([]byte, len(key))
					res = cipher.NewCTR(block, iv)
					return
				},

				KeyLength:               16,
				ResedKeyLength:          16,
				CipherMaxGeneratedBytes: 128,
			},
		}

		tester.Test(t)
	})
}

func BenchmarkRNG_Cipher_WithAES128CTR(b *testing.B) {
	b.Run("without_rekeing", func(b *testing.B) {
		tester := crypkatest.RNGTester{
			Algo: &crypka.EncStreamRNGAlgo{
				CipherFactory: func(key []byte) (res cipher.Stream, err error) {
					block, err := aes.NewCipher(key)
					if err != nil {
						return
					}
					iv := make([]byte, len(key))
					res = cipher.NewCTR(block, iv)
					return
				},

				KeyLength: 16,
			},
		}

		tester.Benchmark(b)
	})

	// note: 1024 is absurdly low value to use
	b.Run("with_rekeing_after_1024", func(b *testing.B) {
		tester := crypkatest.RNGTester{
			Algo: &crypka.EncStreamRNGAlgo{
				CipherFactory: func(key []byte) (res cipher.Stream, err error) {
					block, err := aes.NewCipher(key)
					if err != nil {
						return
					}
					iv := make([]byte, len(key))
					res = cipher.NewCTR(block, iv)
					return
				},

				KeyLength:               16,
				ResedKeyLength:          16,
				CipherMaxGeneratedBytes: 1024,
			},
		}

		tester.Benchmark(b)
	})
}
