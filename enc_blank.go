package crypka

import "io"

// WARNING: This algorithm is FOR TESTING ONLY.
// IT DOES NOTHING, IT JUST COPIES DATA!!!
// It turns out however, to be useful for testing.
type BlankEncSymmAlgo struct {
}

func (algo *BlankEncSymmAlgo) GenerateKey(ctx KeyGenerationContext, rng RNG) (sk EncSymmKey, err error) {
	sk = &blankEncSymmKey{}

	return
}

func (algo *BlankEncSymmAlgo) GetInfo() EncAlgoInfo {
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

func (algo *BlankEncSymmAlgo) ParseSymmEncKey(ctx KeyParseContext, data []byte) (ek EncSymmKey, err error) {
	if len(data) != 0 {
		err = ErrKeyParseField
		return
	}
	ek = &blankEncSymmKey{}
	return
}

type blankEncSymmKey struct {
}

func (k *blankEncSymmKey) MarshalToWriter(w io.Writer) (err error) {
	return
}

func (k *blankEncSymmKey) MakeEncryptor(ctx KeyContext) (enc Encryptor, err error) {
	enc = &blankSymmEncryptor{}
	return
}
func (k *blankEncSymmKey) MakeDecryptor(ctx KeyContext) (dec Decryptor, err error) {
	dec = &blankSymmDecryptor{}
	return
}

type blankSymmEncryptor struct {
}

func (xorED *blankSymmEncryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: false,
		EncType:              EncTypeStream,
	}
}

func (enc *blankSymmEncryptor) Encrypt(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
}

func (xorED *blankSymmEncryptor) Finalize(appendTo []byte) (res []byte, err error) {
	res = appendTo
	return
}

type blankSymmDecryptor struct {
}

func (dec *blankSymmDecryptor) GetEncInfo() EncInfo {
	return EncInfo{
		RequiresFinalization: false,
		EncType:              EncTypeStream,
	}
}

func (xorED *blankSymmDecryptor) Decrypt(in, appendTo []byte) (res []byte, err error) {
	res = append(appendTo, in...)
	return
}

func (xorED *blankSymmDecryptor) Finalize() (err error) {
	return
}
