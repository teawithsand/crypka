package crypka_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestKX_RNG_WithX25519(t *testing.T) {
	tester := crypkatest.KXTester{
		Algo: &crypka.KXRngAlgo{
			KXAlgo: &crypka.X25519KXAlgo{},
			RNGAlgo: &crypka.EncStreamRNGAlgo{
				CipherFactory: func(key []byte) (res cipher.Stream, err error) {
					block, err := aes.NewCipher(key)
					if err != nil {
						return
					}
					iv := make([]byte, len(key))
					res = cipher.NewCTR(block, iv)
					return
				},

				KeyLength:      16,
				ResedKeyLength: 16,
			},
		},
	}

	tester.Test(t)
}
