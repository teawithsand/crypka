package crypka

import "bytes"

type encKxEncryptor struct {
	algo   *EncAsymKXAlgo
	public KXPublic
	ctx    KeyContext

	encoding intEncoding

	wrappedEncryptor Encryptor
	cachedError      error
}

func (enc *encKxEncryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: enc.algo.GetInfo().RequiresFinalization,
		EncType:              enc.algo.GetInfo().EncType,
	}
}

func (enc *encKxEncryptor) Encrypt(in, appendTo []byte) (res []byte, err error) {
	if enc.cachedError != nil {
		err = enc.cachedError
		return
	}

	defer func() {
		if err != nil {
			enc.cachedError = err
		}
	}()

	if enc.wrappedEncryptor != nil {
		return enc.wrappedEncryptor.Encrypt(in, appendTo)
	}

	res = appendTo

	ephPublic, ephSecret, err := enc.algo.KXAlgo.GenerateKXPair(enc.ctx, enc.algo.EphemeralRNG)
	if err != nil {
		return
	}

	buf := make([]byte, enc.algo.KXResultLength)
	err = enc.algo.KXAlgo.PerformExchange(enc.ctx, enc.public, ephSecret, buf)
	if err != nil {
		return
	}

	var keyRNG RNG
	if enc.algo.RNGAlgo == nil {
		keyRNG = bytes.NewReader(buf)
	} else {
		keyRNG, err = enc.algo.RNGAlgo.MakeRng(enc.ctx, buf)
		if err != nil {
			return
		}
	}

	sk, err := enc.algo.EncSymmAlgo.GenerateKey(enc.ctx, keyRNG)
	if err != nil {
		return
	}

	enc.wrappedEncryptor, err = sk.MakeEncryptor(enc.ctx)
	if err != nil {
		return
	}

	ephPubMar, err := MarshalKeyToSlice(ephPublic)
	if err != nil {
		return
	}

	res, _ = enc.encoding.AppendToBuf(res, uint64(len(ephPubMar)))
	res = append(res, ephPubMar...)

	res, err = enc.wrappedEncryptor.Encrypt(in, res)
	return
}

func (enc *encKxEncryptor) Finalize(appendTo []byte) (res []byte, err error) {
	if enc.cachedError != nil {
		err = enc.cachedError
		return
	}

	if enc.GetEncInfo().RequiresFinalization && enc.wrappedEncryptor == nil {
		err = ErrEncAuthFiled
		return
	}
	if enc.wrappedEncryptor != nil {
		return enc.wrappedEncryptor.Finalize(appendTo)
	}
	return
}
