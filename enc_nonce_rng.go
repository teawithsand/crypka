package crypka

import "io"

type RNGNonceManager struct {
	Nonce  []byte
	RNG    io.Reader
	Unsafe bool

	emittedNonceCount uint64
}

func (nm *RNGNonceManager) GetNonce() []byte {
	return nm.Nonce
}

func (nm *RNGNonceManager) NextNonce() (err error) {
	// skip emittedNonceCount check for bigger nonces
	if !nm.Unsafe && len(nm.Nonce) < 64*2/8 {
		// birthday paradox requires us to use square root of value
		if nm.emittedNonceCount >= 1<<(len(nm.Nonce)*8/2) {
			err = ErrEncTooManyChunksEncrypted
			return
		}
	}

	_, err = io.ReadFull(nm.RNG, nm.Nonce)
	if err != nil {
		return
	}

	nm.emittedNonceCount += 1
	return
}

func (nm *RNGNonceManager) Initialize() (err error) {
	_, err = io.ReadFull(nm.RNG, nm.Nonce)
	if err != nil {
		return
	}
	return
}
