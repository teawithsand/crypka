package crypkatest

import "github.com/teawithsand/crypka"

type SignKeyBag struct {
	SignKey crypka.SigningKey
	VerKey  crypka.VerifyingKey

	BaseBag
}

func (bag *SignKeyBag) EnsureValidSymm(algo crypka.SignSymmKeyGen) (err error) {
	if bag.SignKey == nil {
		bag.SignKey, err = algo.GenerateKey(bag.Context, bag.GenerateRNG)
		if err != nil {
			return
		}
	}
	if bag.VerKey == nil {
		bag.VerKey, err = algo.GenerateKey(bag.Context, bag.GenerateRNG)
		if err != nil {
			return
		}
	}
	return
}

func (bag *SignKeyBag) EnsureValidAsym(algo crypka.SignAsymKeyGen) (err error) {
	if bag.SignKey == nil {
		bag.SignKey, _, err = algo.GenerateKeyPair(bag.Context, bag.GenerateRNG)
		if err != nil {
			return
		}
	}
	if bag.VerKey == nil {
		_, bag.VerKey, err = algo.GenerateKeyPair(bag.Context, bag.GenerateRNG)
		if err != nil {
			return
		}
	}
	return
}
