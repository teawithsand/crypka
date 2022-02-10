package crypka

type compressSigner struct {
	ctx          KeyContext
	compressor   Signer
	actualSigner func(ctx KeyContext, data []byte) (sign []byte, err error)
}

func (s *compressSigner) Write(data []byte) (sz int, err error) {
	return s.compressor.Write(data)
}

func (s *compressSigner) Finalize(appendTo []byte) (res []byte, err error) {
	compressedData, err := s.compressor.Finalize(nil)
	if err != nil {
		return
	}

	return s.actualSigner(s.ctx, compressedData)
}

type CompressVerifier struct {
	Ctx            KeyContext
	Compressor     Signer
	ActualVerifier func(ctx KeyContext, sign, data []byte) (err error)
}

func (s *CompressVerifier) Write(data []byte) (sz int, err error) {
	return s.Compressor.Write(data)
}

func (s *CompressVerifier) Verify(sign []byte) (err error) {
	compressedData, err := s.Compressor.Finalize(nil)
	if err != nil {
		return
	}

	return s.ActualVerifier(s.Ctx, sign, compressedData)
}

type CompressSigningKey struct {
	Compressor   SigningKey
	ActualSigner func(ctx KeyContext, data []byte) (sign []byte, err error)
}

func (k *CompressSigningKey) MakeSigner(ctx KeyContext) (signer Signer, err error) {
	compressor, err := k.Compressor.MakeSigner(ctx)
	if err != nil {
		return
	}

	return &compressSigner{
		ctx:          ctx,
		compressor:   compressor,
		actualSigner: k.ActualSigner,
	}, nil
}

type CompressVerifyingKey struct {
	Compressor     SigningKey
	ActualVerifier func(ctx KeyContext, sign, data []byte) (err error)
}

func (k *CompressVerifyingKey) MakeVerifier(ctx KeyContext) (verifier Verifier, err error) {
	compressor, err := k.Compressor.MakeSigner(ctx)
	if err != nil {
		return
	}

	return &CompressVerifier{
		Ctx:            ctx,
		Compressor:     compressor,
		ActualVerifier: k.ActualVerifier,
	}, nil
}
