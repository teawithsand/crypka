package crypka

type CompressSigner struct {
	Ctx          KeyContext
	Compressor   Signer
	ActualSigner func(ctx KeyContext, data []byte) (sign []byte, err error)
}

func (s *CompressSigner) Write(data []byte) (sz int, err error) {
	return s.Compressor.Write(data)
}

func (s *CompressSigner) Finalize(appendTo []byte) (res []byte, err error) {
	compressedData, err := s.Compressor.Finalize(nil)
	if err != nil {
		return
	}

	return s.ActualSigner(s.Ctx, compressedData)
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

	return &CompressSigner{
		Ctx:          ctx,
		Compressor:   compressor,
		ActualSigner: k.ActualSigner,
	}, nil
}

type CompressverifyingKey struct {
	Compressor     SigningKey
	ActualVerifier func(ctx KeyContext, sign, data []byte) (err error)
}

func (k *CompressverifyingKey) MakeVerifier(ctx KeyContext) (verifier Verifier, err error) {
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
