package crypka

import "io"

// Implements algorithm, which handles streamming encryption in crypka's format.
type CPKStreamSymmEncAlgo struct {
	EncSymmAlgo
}

func (algo *CPKStreamSymmEncAlgo) GetInfo() EncAlgoInfo {
	info := algo.EncSymmAlgo.GetInfo()
	info.EncType = EncTypeStream

	if info.AuthMode == EagerAuthetnicated {
		info.AuthMode = EagerAuthetnicated
	} else if info.AuthMode != NotAuthenticated {
		info.AuthMode = LateAuthenticated
	}

	return info
}

func (algo *CPKStreamSymmEncAlgo) GenerateKey(ctx KeyGenerationContext, rng RNG) (key EncSymmKey, err error) {
	inner, err := algo.EncSymmAlgo.GenerateKey(ctx, rng)
	if err != nil {
		return
	}

	key = &cpkStreamEncSymmKey{
		wrapped: inner,
	}

	return
}

func (algo *CPKStreamSymmEncAlgo) ParseSymmEncKey(ctx KeyParseContext, data []byte) (key EncSymmKey, err error) {
	inner, err := algo.EncSymmAlgo.ParseSymmEncKey(ctx, data)
	if err != nil {
		return
	}

	key = &cpkStreamEncSymmKey{
		wrapped: inner,
	}

	return
}

type cpkStreamEncSymmKey struct {
	wrapped EncSymmKey
}

func (ek *cpkStreamEncSymmKey) MakeEncryptor(ctx KeyContext) (enc Encryptor, err error) {
	inner, err := ek.wrapped.MakeEncryptor(ctx)
	if err != nil {
		return
	}

	enc = newCPKStreamEncryptor(inner, 256)
	return
}

func (ek *cpkStreamEncSymmKey) MakeDecryptor(ctx KeyContext) (dec Decryptor, err error) {
	inner, err := ek.wrapped.MakeDecryptor(ctx)
	if err != nil {
		return
	}

	dec = newCPKStreamDecryptor(inner, 1024)
	return
}

func (ek *cpkStreamEncSymmKey) MarshalToWriter(w io.Writer) (err error) {
	mk, ok := ek.wrapped.(MarshalableKey)
	if !ok {
		err = ErrKeyNotMarshalable
		return
	}
	return mk.MarshalToWriter(w)
}
