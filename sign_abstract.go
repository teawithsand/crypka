package crypka

import "io"

type VerifyingKey interface {
	MakeVerifier(ctx KeyContext) (Verifier, error)
}

type Verifier interface {
	io.Writer

	Verify(sign []byte) error
}

type SigningKey interface {
	MakeSigner(key KeyContext) (Signer, error)
}

type Signer interface {
	io.Writer

	Finalize(appendTo []byte) ([]byte, error)
}

type SignAlgoInfo struct {
	BaseAlgorithmInfo
}

type SignAlgo interface {
	GetInfo() SignAlgoInfo
}

// ASYMMETRIC STUFF HERE //

type SignAsymAlgo interface {
	SignAlgo
	SignAsymKeyGen
	SignAsymKeyParser
}

type SignAsymKeyGen interface {
	GenerateKeyPair(ctx KeyGenerationContext) (SigningKey, VerifyingKey, error)
}

type SignAsymKeyParser interface {
	ParseSigningKey(ctx KeyParseContext, data []byte) (SigningKey, error)
	ParseVerifyingKey(ctx KeyParseContext, data []byte) (VerifyingKey, error)
}

// SYMMETRIC STUFF HERE //

type SignSymmAlgo interface {
	SignAlgo
	SignSymmKeyGen
	SignSymmKeyParser
}

type SignSymmKeyGen interface {
	GenerateKey(ctx KeyGenerationContext) (SymmSignKey, error)
}

type SignSymmKeyParser interface {
	ParseSymmSignKey(ctx KeyParseContext, data []byte) (SymmSignKey, error)
}

// SymmSignKey even though, it at first sight may seem useless, its quite useful.
// Usually this is implemented by HMACs and hashers(in case of hashes key is always constant and zero-length, but abstraction still works).
type SymmSignKey interface {
	SigningKey
	VerifyingKey
}

// ALGO STUFF //
