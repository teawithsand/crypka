package crypka

type EncKey interface {
	MakeEncryptor(ctx KeyContext) (Encryptor, error)
}

type DecKey interface {
	MakeDecryptor(ctx KeyContext) (Decryptor, error)
}

// Encryptor is something capable of encrypting data.
// It works in either chunk-by-chunk mode, where sizes of in argument during subsequent calls matter
// and stream mode, which do not apply that restriction.
//
// It handles all kinds of enctyptions: stream, block, AEAD and other kinds of encryption.
// If finalization or something is required it's user responsibility to cast this to appropraite interface, which can handle that.
type Encryptor interface {
	Encrypt(in, appendTo []byte) (res []byte, err error)
}

// Decryptor is able to reverse transformation done by Encryptor.
// If finalization or something is required it's user responsibility to cast this to appropraite interface, which can handle that.
type Decryptor interface {
	Decrypt(in, appendTo []byte) (res []byte, err error)
}

// TODO(teawithsand): primitives for handling streamming encryption, like streamming encryptor/decryptor

type EncAlgoInfo struct {
	BaseAlgorithmInfo
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
	GenerateKey(ctx KeyGenerationContext) (SymmEncKey, error)
}

type EncSymmKeyParser interface {
	ParseSymmEncKey(ctx KeyParseContext, data []byte) (SymmEncKey, error)
}

type SymmEncKey interface {
	EncKey
	DecKey
}
