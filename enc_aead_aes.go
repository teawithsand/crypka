package crypka

import (
	"crypto/aes"
	"crypto/cipher"
)

func aesAeadFactory(key []byte) (aead cipher.AEAD, err error) {
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

// Registers AES128GCM ciphers with nonce coutner and rng
func RegisterAES128GCM(reg Registry) {
	reg.RegisterAlgo("aes-128-gcm-counter", &AEADSymmEncAlgo{
		KeyLength:   128 / 8,
		NonceLength: 12,
		NonceConfig: NonceConfig{
			NonceType: CounterNonce,
		},
		AEADFactory: aesAeadFactory,
	})
	reg.RegisterAlgo("aes-128-gcm-rng", &AEADSymmEncAlgo{
		KeyLength:   128 / 8,
		NonceLength: 12,
		NonceConfig: NonceConfig{
			NonceType: RNGNonce,
		},
		AEADFactory: aesAeadFactory,
	})
}
