package crypka

import "io"

// WARNING: This algorithm is FOR TESTING ONLY.
// DO NOT USE IT IN PRODUCTION ANYTIME EVER!
type XorEncSymmAlgo struct {
	MinKeyLength      int
	MaxKeyLength      int
	GenerateKeyLength int
}

func (algo *XorEncSymmAlgo) GenerateKey(ctx KeyGenerationContext) (sk EncSymmKey, err error) {
	key := make([]byte, algo.GenerateKeyLength)
	rng := ContextGetRNG(ctx)
	_, err = io.ReadFull(rng, key)
	if err != nil {
		return
	}

	sk = &xorEncSymmKey{
		key: key,
	}

	return
}

func (algo *XorEncSymmAlgo) GetInfo() EncAlgoInfo {
	return EncAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     SymmEncAlgorithmType,
			IsSecure: false,
		},
		EncInfo: EncInfo{
			RequiresFinalization: false,
			EncType:              EncTypeStream,
		},
		AuthMode: NotAuthenticated,
	}
}

func (algo *XorEncSymmAlgo) ParseSymmEncKey(ctx KeyParseContext, data []byte) (ek EncSymmKey, err error) {
	if algo.MinKeyLength >= 0 && len(data) < algo.MinKeyLength {
		err = ErrKeyParseField
		return
	}
	if algo.MaxKeyLength >= 0 && len(data) > algo.MaxKeyLength {
		err = ErrKeyParseField
		return
	}

	keyCopy := make([]byte, len(data))
	copy(keyCopy, data)

	ek = &xorEncSymmKey{
		key: keyCopy,
	}
	return
}

type xorEncSymmKey struct {
	key []byte
}

func (k *xorEncSymmKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(k.key)
	return
}

func (k *xorEncSymmKey) MakeEncryptor(ctx KeyContext) (enc Encryptor, err error) {
	enc = &xorSymmEncryptor{
		key: k.key,
	}
	return
}
func (k *xorEncSymmKey) MakeDecryptor(ctx KeyContext) (dec Decryptor, err error) {
	dec = &xorSymmDecryptor{
		key: k.key,
	}
	return
}

type xorSymmEncryptor struct {
	key []byte
	pos int
}

func (xorED *xorSymmEncryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: false,
		EncType:              EncTypeStream,
	}
}

func (enc *xorSymmEncryptor) Encrypt(in, appendTo []byte) (res []byte, err error) {
	res = appendTo

	for _, b := range in {
		res = append(res, b^enc.key[enc.pos])
		enc.pos = (enc.pos + 1) % len(enc.key)
	}

	return
}

func (xorED *xorSymmEncryptor) Finalize(appendTo []byte) (res []byte, err error) {
	res = appendTo
	return
}

type xorSymmDecryptor struct {
	key []byte
	pos int
}

func (dec *xorSymmDecryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: false,
		EncType:              EncTypeStream,
	}
}

func (xorED *xorSymmDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	res = appendTo

	for _, b := range in {
		res = append(res, b^xorED.key[xorED.pos])
		xorED.pos = (xorED.pos + 1) % len(xorED.key)
	}

	return
}

func (xorED *xorSymmDecryptor) Finalize() (err error) {
	return
}
