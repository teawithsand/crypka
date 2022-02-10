package crypka

type EncKey interface {
	MakeEncryptor(ctx KeyContext) (Encryptor, error)
}

type DecKey interface {
	MakeDecryptor(ctx KeyContext) (Decryptor, error)
}

// ENCRYPTOR STUFF //

// Defines relations between subsequent call to Encrypt/Decrypt functions.
// See specific types for more details.
type EncType uint8

const (
	// Block encryption encrypts(decrypts) each block atomically.
	// Blocks are independent of each other.
	//
	// Note: this should not be mistaken with block encryption from crypto world in general ie. fixed block size.
	// This one is more like AEAD encryption(think of box/sealedbox from nacl)
	EncTypeBlock EncType = 1

	// This kind of encryption requires that chunks passed for decryption are passed in same order(it MAY NOT be checked however)
	// that they were passed for encryption.
	//
	// Also no slicing is allowed. Each chunk yielded from encrypt must be passed in same and unmodified form to decrypt.
	EncTypeChain EncType = 2

	// It's just like EncTypeChain, but allows slicing. Passing partial chunks to decrypt is allowed.
	EncTypeStream EncType = 3
)

// Note: this structure contains only basic information about encryption algorithm.
// In particular kind and if it requires finalization.
//
// For more information about specified encryption scheme algorithm should be used.
type EncInfo struct {
	RequiresFinalization bool
	EncType              EncType
}

type Encryptor interface {
	GetEncInfo() EncInfo

	Encrypt(in, appendTo []byte) (res []byte, err error)
	Finalize(appendTo []byte) (res []byte, err error)
}

type Decryptor interface {
	GetEncInfo() EncInfo

	Decrypt(in, appendTo []byte) (res []byte, err error)
	Finalize() (err error)
}

type EncAlgoInfo struct {
	BaseAlgorithmInfo
	EncInfo
}

type EncAlgo interface {
	GetInfo() EncAlgoInfo
}

// ASYMMETRIC STUFF HERE //

type EncAsymAlgo interface {
	EncAlgo
	EncAsymKeygen
	EncAsymKeyParser
}

type EncAsymKeygen interface {
	GenerateKeyPair(ctx KeyGenerationContext) (EncKey, DecKey, error)
}

type EncAsymKeyParser interface {
	ParseEncKey(ctx KeyParseContext, data []byte) (EncKey, error)
	ParseDecKey(ctx KeyParseContext, data []byte) (DecKey, error)
}

// SYMMETRIC STUFF HERE //

type EncSymmAlgo interface {
	EncAlgo
	EncSymmKeygen
	EncSymmKeyParser
}

type EncSymmKeygen interface {
	GenerateKey(ctx KeyGenerationContext) (EncSymmKey, error)
}

type EncSymmKeyParser interface {
	ParseSymmEncKey(ctx KeyParseContext, data []byte) (EncSymmKey, error)
}

type EncSymmKey interface {
	EncKey
	DecKey
}
