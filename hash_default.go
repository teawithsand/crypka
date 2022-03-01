package crypka

type StructHasherImpl struct {
	// Note: SK given *should* be hash.
	SigningKey SigningKey
	Writer     StructHashWriter // optional; default used if unset
}

func (sh *StructHasherImpl) HashStruct(ctx HashContext, data interface{}) (res []byte, err error) {
	writer := sh.Writer
	if writer == nil {
		writer = &DefaultStructHashWriter{}
	}

	signer, err := sh.SigningKey.MakeSigner(ctx)
	if err != nil {
		return
	}

	err = sh.Writer.WriteStruct(ctx, data, signer)
	if err != nil {
		return
	}

	res, err = signer.Finalize(nil)
	if err != nil {
		return
	}
	return
}
