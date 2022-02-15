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

type KXAlgo interface {
	KXParser
	KXExchanger
	GetInfo() KXAlgorithmInfo
}

type KXAlgorithmInfo struct {
	BaseAlgorithmInfo
}
