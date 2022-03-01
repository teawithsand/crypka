package crypka_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestEnc_KX_WithEd25519_WithAES128GCM_WithXorEnc(t *testing.T) {
	ephemeralRngAlgo := &crypka.MathRNGAlgo{}
	rng, err := ephemeralRngAlgo.MakeRng(nil, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Error(err)
		return
	}
	tester := crypkatest.EncAsymTester{
		Algo: &crypka.EncAsymKXAlgo{
			EncSymmAlgo: &crypka.AEADSymmEncAlgo{
				KeyLength:   16,
				NonceLength: 12,
				NonceConfig: crypka.NonceConfig{
					NonceType: crypka.CounterNonce,
				},
				AEADFactory: func(key []byte) (aead cipher.AEAD, err error) {
					cph, err := aes.NewCipher(key)
					if err != nil {
						return
					}
					aead, err = cipher.NewGCMWithNonceSize(cph, 12)
					return
				},
			},
			KXAlgo:         &crypka.X25519KXAlgo{},
			KXResultLength: 16,
			EphemeralRNG:   rng,
		},
	}

	tester.Test(t)
}
