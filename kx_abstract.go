package crypka

type KXPublic interface {
}
type KXSecret interface {
}

type KXParser interface {
	ParseKXPublic(ctx KeyParseContext, data []byte) (KXPublic, error)
	ParseKXSecret(ctx KeyParseContext, data []byte) (KXSecret, error)
}

type KXExchanger interface {
	PerformExchange(ctx KeyContext, public KXPublic, secret KXSecret, res []byte) (err error)
}

type KXKeygen interface {
	GenerateKXPair(ctx KeyGenerationContext) (public KXPublic, secret KXSecret, err error)
}

type KXAlgo interface {
	KXParser
	KXExchanger
	KXKeygen
	GetInfo() KXAlgorithmInfo
}

type KXAlgorithmInfo struct {
	BaseAlgorithmInfo
}
