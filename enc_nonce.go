package crypka

type NonceType uint8

const (
	// Instructs algorithm to use nonce counter to manage nonces.
	// Allows producing 2^(bytes of nonce) blocks.
	//
	// WARNING! After using this mode nothing should be encrypted with the same key.
	CounterNonce NonceType = 1

	// Instructs algorithm to use RNG to manage nonces.
	// Allows producing 2^(bytes of nonce / 2) blocks.
	//
	// WARNING when using multiple encryptors for encryption it's user responsibility not to exceed above number.
	// Note: some algorithms like XChaCha20 have nonce so big, that for any real world usage infinite amount of ciphertexts may be produced.
	RNGNonce NonceType = 2
)

// Defines how specified algoritm should manage nonce.
// Please note that changing it may change algorithm characteristics.
type NonceConfig struct {
	NonceType NonceType

	// If true, disables all checks in encryptor, which prevent user from producing too many ciphertexts.
	AllowUnsafe bool
}

type NonceManager interface {
	GetNonce() []byte
	NextNonce() (err error)
}

func (config *NonceConfig) MakeNonceManager(ctx KeyContext, length int) (nm NonceManager, err error) {
	if config.NonceType == CounterNonce {
		nm = &CounterNonceManager{
			Nonce:  make([]byte, length),
			Unsafe: config.AllowUnsafe,
		}
		return
	} else if config.NonceType == RNGNonce {
		rngManager := &RNGNonceManager{
			Nonce:  make([]byte, length),
			Unsafe: config.AllowUnsafe,
			RNG:    ContextGetRNG(ctx),
		}
		err = rngManager.Initialize()
		if err != nil {
			return
		}

		nm = rngManager
		return
	} else {
		err = ErrInvalidNonceType
		return
	}
}
