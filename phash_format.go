package crypka

// PasswordHashParserImpl, which uses inner parser map to parse hash for each algorithm.
type PasswordHashParserImpl struct {
	Parsers map[string]func(rest []byte) (res PasswordHash, err error)
}

func (p *PasswordHashParserImpl) ParsePasswordHash(ctx PasswordHashContext, hash []byte) (res PasswordHash, err error) {
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
