package crypka

import (
	"crypto/cipher"
	"io"
)

type AEADSymmEncAlgo struct {
	KeyLength   int
	NonceLength int

	NonceConfig NonceConfig

	AEADFactory func(key []byte) (aead cipher.AEAD, err error)
}

func (algo *AEADSymmEncAlgo) makeKey(ctx AnyContext, data []byte) (key *aeadSymmEncKey, err error) {
	key = &aeadSymmEncKey{
		key:             data,
		aeadFactory:     algo.AEADFactory,
		nonceConfig:     algo.NonceConfig,
		algoNonceLength: algo.NonceLength,
	}
	return
}

func (algo *AEADSymmEncAlgo) GenerateKey(ctx KeyGenerationContext) (key EncSymmKey, err error) {
	data := make([]byte, algo.KeyLength)
	rng := ContextGetRNG(ctx)
	_, err = io.ReadFull(rng, data)
	if err != nil {
		return
	}

	key, err = algo.makeKey(ctx, data)
	return
}

func (algo *AEADSymmEncAlgo) GetInfo() EncAlgoInfo {
	var encType EncType
	if algo.NonceConfig.NonceType == CounterNonce {
		encType = EncTypeChain
	} else if algo.NonceConfig.NonceType == RNGNonce {
		encType = EncTypeBlock
	} else {
		panic(ErrInvalidNonceType)
	}

	return EncAlgoInfo{
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     SymmEncAlgorithmType,
			IsSecure: true,
		},
		EncInfo: EncInfo{
			RequiresFinalization: false,
			EncType:              encType,
		},
		AuthMode: LateSoftAuthenticated,
	}
}

func (algo *AEADSymmEncAlgo) ParseSymmEncKey(ctx KeyParseContext, data []byte) (key EncSymmKey, err error) {
	if len(data) != algo.KeyLength {
		err = ErrKeyParseField
		return
	}

	keyCopy := make([]byte, len(data))
	copy(keyCopy, data)

	key, err = algo.makeKey(ctx, keyCopy)
	return
}

type aeadSymmEncKey struct {
	key             []byte
	nonceConfig     NonceConfig
	algoNonceLength int
	aeadFactory     func(key []byte) (aead cipher.AEAD, err error)
}

func (key *aeadSymmEncKey) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(key.key)
	return
}

func (key *aeadSymmEncKey) makeNonceManager(ctx KeyContext, aeadLength int) (nonceManager NonceManager, embedNonce bool, err error) {
	embedNonce = key.nonceConfig.NonceType == RNGNonce
	nonceManager, err = key.nonceConfig.MakeNonceManager(ctx, aeadLength)
	if err != nil {
		return
	}

	if aeadLength != key.algoNonceLength {
		panic("aead nonce length != algo nonce length; these values must match")
	}

	return
}

func (key *aeadSymmEncKey) MakeEncryptor(ctx KeyContext) (enc Encryptor, err error) {
	aead, err := key.aeadFactory(key.key)
	if err != nil {
		return
	}

	nonceManager, embbedNonce, err := key.makeNonceManager(ctx, aead.NonceSize())
	if err != nil {
		return
	}

	enc = &aeadEncryptor{
		embedNonce:   embbedNonce,
		nonceManager: nonceManager,
		aead:         aead,
	}

	return
}

type aeadEncryptor struct {
	embedNonce bool

	nonceManager NonceManager
	aead         cipher.AEAD
	cachedError  error
}

func (key *aeadSymmEncKey) MakeDecryptor(ctx KeyContext) (dec Decryptor, err error) {
	aead, err := key.aeadFactory(key.key)
	if err != nil {
		return
	}

	nonceManager, embbedNonce, err := key.makeNonceManager(ctx, aead.NonceSize())
	if err != nil {
		return
	}

	var embedNonceLength int
	if embbedNonce {
		nonceManager = nil
		embedNonceLength = aead.NonceSize()
	}

	dec = &aeadDecryptor{
		embedNonceLength: embedNonceLength,
		nonceManager:     nonceManager,
		aead:             aead,
	}
	return
}

func (enc *aeadEncryptor) GetEncInfo() EncInfo {
	var ty EncType
	if enc.embedNonce {
		ty = EncTypeChain
	} else {
		ty = EncTypeBlock
	}
	return EncInfo{
		RequiresFinalization: false,
		EncType:              ty,
	}
}

func (enc *aeadEncryptor) Encrypt(in, appendTo []byte) (res []byte, err error) {
	if enc.cachedError != nil {
		err = enc.cachedError
		return
	}

	res = appendTo

	nonce := enc.nonceManager.GetNonce()

	res = enc.aead.Seal(res, nonce, in, nil)
	if enc.embedNonce {
		res = append(res, nonce...)
	}

	enc.cachedError = enc.nonceManager.NextNonce()
	return
}

func (enc *aeadEncryptor) Finalize(appendTo []byte) (res []byte, err error) {
	res = appendTo
	return
}

type aeadDecryptor struct {
	nonceManager     NonceManager
	embedNonceLength int

	aead        cipher.AEAD
	cachedError error
}

func (enc *aeadDecryptor) GetEncInfo() EncInfo {
	var ty EncType
	if enc.nonceManager == nil {
		ty = EncTypeChain
	} else {
		ty = EncTypeBlock
	}
	return EncInfo{
		RequiresFinalization: false,
		EncType:              ty,
	}
}

func (dec *aeadDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	if dec.cachedError != nil {
		err = dec.cachedError
		return
	}
	res = appendTo

	var nonce []byte
	if dec.nonceManager != nil {
		nonce = dec.nonceManager.GetNonce()
	} else {
		if len(in) < dec.embedNonceLength {
			err = ErrDecryptionAuthFiled
			return
		}

		nonce = in[len(in)-dec.embedNonceLength:]
		in = in[:len(in)-dec.embedNonceLength]
	}

	res, err = dec.aead.Open(res, nonce, in, nil)
	if err != nil {
		err = ErrDecryptionAuthFiled
		return
	}

	if dec.nonceManager != nil {
		dec.cachedError = dec.nonceManager.NextNonce()
	}
	return
}

func (enc *aeadDecryptor) Finalize() (err error) {
	return
}
