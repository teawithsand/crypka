package crypka

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

type X25519KXAlgo struct{}

func (algo *X25519KXAlgo) GetInfo() KXAlgorithmInfo {
	return KXAlgorithmInfo{
		MaxResLen: 32,
		BaseAlgorithmInfo: BaseAlgorithmInfo{
			Type:     KXAlgorithmType,
			IsSecure: true,
		},
	}
}

func (algo *X25519KXAlgo) GenerateKXPair(ctx KeyGenerationContext, rng RNG) (public KXPublic, secret KXSecret, err error) {
	rng = FallbackContextGetRNG(ctx, rng)

	var secretBuf [curve25519.ScalarSize]byte
	_, err = io.ReadFull(rng, secretBuf[:])
	if err != nil {
		return
	}

	var publicBuf [curve25519.PointSize]byte
	curve25519.ScalarBaseMult(&publicBuf, &secretBuf)

	public = &x25519KXPublic{
		data: publicBuf,
	}

	secret = &x25519KXSecret{
		data: secretBuf,
	}
	return
}

func (algo *X25519KXAlgo) ParseKXPublic(ctx KeyParseContext, data []byte) (pub KXPublic, err error) {
	if len(data) != curve25519.PointSize {
		err = ErrKeyParseField
		return
	}

	var buf [curve25519.PointSize]byte
	copy(buf[:], data)

	pub = &x25519KXPublic{
		data: buf,
	}
	return
}

func (algo *X25519KXAlgo) ParseKXSecret(ctx KeyParseContext, data []byte) (sec KXSecret, err error) {
	if len(data) != curve25519.ScalarSize {
		err = ErrKeyParseField
		return
	}

	var buf [curve25519.ScalarSize]byte
	copy(buf[:], data)

	sec = &x25519KXSecret{
		data: buf,
	}

	return
}

func (algo *X25519KXAlgo) PerformExchange(ctx KeyContext, public KXPublic, secret KXSecret, res []byte) (err error) {
	if len(res) > 32 {
		err = ErrInvalidKXDestination
		return
	}

	typedPublic, ok := public.(*x25519KXPublic)
	if !ok {
		err = ErrUnsupportedKXPart
		return
	}

	typedSecret, ok := secret.(*x25519KXSecret)
	if !ok {
		err = ErrUnsupportedKXPart
		return
	}

	kxDest, err := curve25519.X25519(typedSecret.data[:], typedPublic.data[:])
	if err != nil {
		return
	}

	copy(res[:], kxDest[:])

	return
}

type x25519KXPublic struct {
	data [curve25519.PointSize]byte
}

func (pub *x25519KXPublic) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(pub.data[:])
	return
}

type x25519KXSecret struct {
	data [curve25519.PointSize]byte
}

func (sec *x25519KXSecret) MarshalToWriter(w io.Writer) (err error) {
	_, err = w.Write(sec.data[:])
	return
}
