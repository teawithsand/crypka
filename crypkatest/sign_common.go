package crypkatest

func SignAndVerifyData(signerChunks [][]byte, verifierChunks [][]byte, bag SignKeyBag) (err error) {
	sig, err := bag.SignKey.MakeSigner(nil)
	if err != nil {
		return
	}
	ver, err := bag.VerKey.MakeVerifier(nil)
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
