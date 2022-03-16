package crypka

type PHashAlgoInfo struct {
	Name   string
	Secure bool
}

// PHasher are special kind of hashes.
// Rather than stream data, they accept constant-sized data and yield hash of it.
type PHasher interface {
	GetInfo() PHashAlgoInfo
	HashPassword(ctx PasswordHashContext, password []byte, appendTo []byte) (res []byte, err error)
	CheckPassword(ctx PasswordHashContext, password, hash []byte) (err error)
}

type PHash interface {
	GetAlgo() string // returns name of hashing algorithm used
	Raw() []byte     // returns encoded form of hash, so if it was parsed again, it would yield same result
}

/*
type PHashParser interface {
	ParsePasswordHash(ctx PasswordHashContext, hash []byte) (res PHash, err error)
}


// PasswordHashParserImpl, which uses inner parser map to parse hash for each algorithm.
type PasswordHashParserImpl struct {
	Parsers map[string]func(rest []byte) (res PHash, err error)
}

func (p *PasswordHashParserImpl) ParsePasswordHash(ctx PasswordHashContext, hash []byte) (res PHash, err error) {
	algo, err := parseAlgo(hash)
	if err != nil {
		return
	}

	parser, ok := p.Parsers[string(algo)]
	if !ok {
		err = ErrPasswordHashUnknownAlgo
		return
	}

	res, err = parser(hash[len(algo)+2:])
	return
}
*/
