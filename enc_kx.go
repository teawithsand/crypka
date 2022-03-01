package crypka

import "io"

// TODO(teawithsand): make this algorithm stream-capable if underlying algo is stream capable as well.

// EncAsymKXAlgo makes asymmetric encryption algorithm from symmetric encryption one and key exchange one.
// It's secure, unless used algorithms are secure.
// Since X25519 exists, it's preferred way to implement asymmetric encryption in application, when used along with
// ChaCha or AES.
type EncAsymKXAlgo struct {
	EncSymmAlgo EncSymmAlgo
	KXAlgo      KXAlgo

	// Max size of ephemeral key length.
	// Ignored during encryption, used for decryption only.
	// Defaults to 1MB.
	MaxMarshaledEphemeralLength int

	// How many bytes should be loaded from KX.
	KXResultLength int

	// Optional, used to extend KX result to key.
	// Raw value used, if not present.
	// Value is truncated to as many bytes as needed by symmetric algo.
	RNGAlgo RNGAlgo

	// RNG to use to generate ephemeral keys.
	// One from context used if nil.
	EphemeralRNG RNG

	// For now block mode is NIY
	//
	// Makes encryptor behave like block one.
	// Generates and embbeds new ephemeral key each time chunk is encrypted.
	// BlockMode bool
}

func (algo *EncAsymKXAlgo) GetInfo() EncAlgoInfo {
	info := algo.EncSymmAlgo.GetInfo()
	kxInfo := algo.KXAlgo.GetInfo()

	info.IsSecure = info.IsSecure && kxInfo.IsSecure
	if algo.RNGAlgo != nil {
		info.IsSecure = info.IsSecure && algo.RNGAlgo.GetInfo().IsSecure
	}

	if info.EncType == EncTypeBlock {
		info.EncType = EncTypeChain
		// since we are generating ephemeral key
		// we can't prevent chunk reordering
		// thus all guarantees about authentication must disappear
		info.AuthMode = NotAuthenticatedEncAuthMode
	} else if info.EncType == EncTypeStream {
		info.EncType = EncTypeChain
	}

	return info
}

func (algo *EncAsymKXAlgo) GenerateKeyPair(ctx KeyGenerationContext, rng RNG) (ek EncKey, dk DecKey, err error) {
	public, secret, err := algo.KXAlgo.GenerateKXPair(ctx, rng)
	if err != nil {
		return
	}

	ek = &encAsymKXAlgoEncKey{
		algo:   algo,
		public: public,
	}
	dk = &encAsymKXAlgoDecKey{
		algo:   algo,
		secret: secret,
	}
	return
}

func (algo *EncAsymKXAlgo) ParseEncKey(ctx KeyParseContext, data []byte) (ek EncKey, err error) {
	kxPublic, err := algo.KXAlgo.ParseKXPublic(ctx, data)
	if err != nil {
		return
	}

	ek = &encAsymKXAlgoEncKey{
		algo:   algo,
		public: kxPublic,
	}
	return
}

func (algo *EncAsymKXAlgo) ParseDecKey(ctx KeyParseContext, data []byte) (dk DecKey, err error) {
	kxSecret, err := algo.KXAlgo.ParseKXSecret(ctx, data)
	if err != nil {
		return
	}

	dk = &encAsymKXAlgoDecKey{
		algo:   algo,
		secret: kxSecret,
	}
	return
}

type encAsymKXAlgoEncKey struct {
	public KXPublic
	algo   *EncAsymKXAlgo
}

func (ek *encAsymKXAlgoEncKey) MarshalToWriter(w io.Writer) (err error) {
	return MarshalKey(ek.public, w)
}

func (ek *encAsymKXAlgoEncKey) MakeEncryptor(ctx KeyContext) (enc Encryptor, err error) {
	enc = &encKxEncryptor{
		algo:   ek.algo,
		public: ek.public,
		ctx:    ctx,
	}
	return
}

type encAsymKXAlgoDecKey struct {
	secret KXSecret
	algo   *EncAsymKXAlgo
}

func (ek *encAsymKXAlgoDecKey) MarshalToWriter(w io.Writer) (err error) {
	return MarshalKey(ek.secret, w)
}

func (ek *encAsymKXAlgoDecKey) MakeDecryptor(ctx KeyContext) (dec Decryptor, err error) {
	dec = &encKxDecryptor{
		algo:   ek.algo,
		secret: ek.secret,
		ctx:    ctx,
	}
	return
}
