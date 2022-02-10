package crypka

type AlgorithmType uint8

const (
	SymmEncAlgorithmType  AlgorithmType = 1
	AsymEncAlgorithmType  AlgorithmType = 2
	HashAlgorithmType     AlgorithmType = 3
	SymmSignAlgorithmType AlgorithmType = 4
	AsymSignAlgorithmType AlgorithmType = 5
)

type BaseAlgorithmInfo struct {
	Type AlgorithmType

	// Is this algorithm cryptographically secure.
	// This may change if algorithm is discovered to be insecure.
	IsSecure bool
}
