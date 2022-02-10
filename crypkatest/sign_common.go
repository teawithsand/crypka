package crypkatest

import (
	"github.com/teawithsand/crypka"
)

func SignAndVerifyData(signerChunks [][]byte, verifierChunks [][]byte, sk crypka.SigningKey, vk crypka.VerifyingKey) (err error) {
	sig, err := sk.MakeSigner(nil)
	if err != nil {
		return
	}
	ver, err := vk.MakeVerifier(nil)
	if err != nil {
		return
	}

	for _, data := range signerChunks {
		_, err = sig.Write(data)
		if err != nil {
			return
		}
	}

	sign, err := sig.Finalize(nil)
	if err != nil {
		return
	}

	for _, data := range verifierChunks {
		_, err = ver.Write(data)
		if err != nil {
			return
		}
	}

	err = ver.Verify(sign)
	return
}
