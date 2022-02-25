package crypka

import "io"

// Note: this type might change in future, when we run out of values on uint8
type cpkControlValue uint8

func (v *cpkControlValue) decode(encoded uint64) (ok bool) {
	if encoded != uint64(streamEndCpkControlByte) {
		ok = false
	} else {
		*v = cpkControlValue(encoded)
		ok = true
	}
	return
}

func (v cpkControlValue) toEncodable() uint64 {
	return uint64(v)
}

const (
	streamEndCpkControlByte cpkControlValue = 0
)

// Implements algorithm, which handles streamming encryption in crypka's format.
type CPKStreamSymmEncAlgo struct {
	EncSymmAlgo
}

func (algo *CPKStreamSymmEncAlgo) GetInfo() EncAlgoInfo {
	info := algo.EncSymmAlgo.GetInfo()
	info.EncType = EncTypeStream

	if info.AuthMode.IsFinalizeAuthetnicated() || info.AuthMode.IsEagerAuthenticated() {
		info.AuthMode.SetTruncAuthenticated(true)
	}

	info.EncInfo.RequiresFinalization = true

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
