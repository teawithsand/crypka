package crypka_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TesEnc_AES128GCM_CanRegister(t *testing.T) {
	reg := crypka.NewRegistry()

	crypka.RegisterAES128GCM(reg)
}

func TestEnc_AES128GCM(t *testing.T) {
	aeadFactory := func(key []byte) (aead cipher.AEAD, err error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return
		}

		aead, err = cipher.NewGCMWithNonceSize(block, 12)
		if err != nil {
			return
		}

		return
	}
	t.Run("counter_nonce", func(t *testing.T) {
		algo := &crypka.AEADSymmEncAlgo{
			KeyLength:   128 / 8,
			NonceLength: 12,
			NonceConfig: crypka.NonceConfig{
				NonceType: crypka.CounterNonce,
			},
			AEADFactory: aeadFactory,
		}
		tester := crypkatest.EncSymmTester{
			Algo: algo,
		}
		tester.Test(t)
	})
	t.Run("rng_nonce", func(t *testing.T) {
		algo := &crypka.AEADSymmEncAlgo{
			KeyLength:   128 / 8,
			NonceLength: 12,
			NonceConfig: crypka.NonceConfig{
				NonceType: crypka.RNGNonce,
			},
			AEADFactory: aeadFactory,
		}
		tester := crypkatest.EncSymmTester{
			Algo: algo,
		}
		tester.Test(t)
	})
}
