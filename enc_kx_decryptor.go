package crypka

import "bytes"

type encKxDecryptor struct {
	algo   *EncAsymKXAlgo
	secret KXSecret
	ctx    KeyContext

	encoding intEncoding

	wrappedDecryptor Decryptor
	cachedError      error
}

func (dec *encKxDecryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: dec.algo.GetInfo().RequiresFinalization,
		EncType:              dec.algo.GetInfo().EncType,
	}
}

func (dec *encKxDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	defer func() {
		if err != nil {
			dec.cachedError = err
		}
	}()

	if dec.wrappedDecryptor != nil {
		return dec.wrappedDecryptor.Decrypt(in, appendTo)
	}

	res = appendTo

	value, valueSz, err := dec.encoding.DecodeAtStart(in)
	if err != nil {
		return
	}
	in = in[valueSz:]

	if dec.algo.MaxMarshaledEphemeralLength > 0 {
		if value > 1<<20 {
			err = ErrEncStreamChunkTooBig
			return
		}
	} else {
		if value > uint64(dec.algo.MaxMarshaledEphemeralLength) {
			err = ErrEncStreamChunkTooBig
			return
		}
	}

	if uint64(len(in)) < value {
		err = ErrEncStreamCorrupted
		return
	}

	rawEphermeralPublic := in[:int(value)]
	ephPublic, err := dec.algo.KXAlgo.ParseKXPublic(dec.ctx, rawEphermeralPublic)
	if err != nil {
		return
	}

	in = in[len(rawEphermeralPublic):]

	buf := make([]byte, dec.algo.KXResultLength)
	err = dec.algo.KXAlgo.PerformExchange(dec.ctx, ephPublic, dec.secret, buf)
	if err != nil {
		return
	}

	var keyRNG RNG
	if dec.algo.RNGAlgo != nil {
		keyRNG = bytes.NewReader(buf)
	} else {
		keyRNG, err = dec.algo.RNGAlgo.MakeRng(dec.ctx, buf)
		if err != nil {
			return
		}
	}

	sk, err := dec.algo.EncSymmAlgo.GenerateKey(dec.ctx, keyRNG)
	if err != nil {
		return
	}

	dec.wrappedDecryptor, err = sk.MakeDecryptor(dec.ctx)
	if err != nil {
		return
	}

	res, err = dec.wrappedDecryptor.Decrypt(in, res)
	return
}

func (dec *encKxDecryptor) Finalize() (err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}

	if dec.GetEncInfo().RequiresFinalization && dec.wrappedDecryptor == nil {
		err = ErrEncAuthFiled
		return
	}
	if dec.wrappedDecryptor != nil {
		return dec.wrappedDecryptor.Finalize()
	}
	return
}
