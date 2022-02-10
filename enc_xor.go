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

	sk = &XorEncSymmKey{
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

	ek = &XorEncSymmKey{
		key: keyCopy,
	}
	return
}

type XorEncSymmKey struct {
	key []byte
}

func (k *XorEncSymmKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(k.key)
	return
}

func (k *XorEncSymmKey) MakeEncryptor(ctx KeyContext) (enc Encryptor, err error) {
	enc = &XorSymmEncryptor{
		key: k.key,
	}
	return
}
func (k *XorEncSymmKey) MakeDecryptor(ctx KeyContext) (dec Decryptor, err error) {
	dec = &XorSymmDecryptor{
		key: k.key,
	}
	return
}

type XorSymmEncryptor struct {
	key []byte
	pos int
}

func (xorED *XorSymmEncryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: false,
		EncType:              EncTypeStream,
	}
}

func (enc *XorSymmEncryptor) Encrypt(in, appendTo []byte) (res []byte, err error) {
	res = appendTo

	for _, b := range in {
		res = append(res, b^enc.key[enc.pos])
		enc.pos = (enc.pos + 1) % len(enc.key)
	}

	return
}

func (xorED *XorSymmEncryptor) Finalize(appendTo []byte) (res []byte, err error) {
	res = appendTo
	return
}

type XorSymmDecryptor struct {
	key []byte
	pos int
}

func (dec *XorSymmDecryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: false,
		EncType:              EncTypeStream,
	}
}

func (xorED *XorSymmDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	res = appendTo

	for _, b := range in {
		res = append(res, b^xorED.key[xorED.pos])
		xorED.pos = (xorED.pos + 1) % len(xorED.key)
	}

	return
}

func (xorED *XorSymmDecryptor) Finalize() (err error) {
	return
}
