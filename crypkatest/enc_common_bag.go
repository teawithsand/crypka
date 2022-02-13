package crypkatest

import "github.com/teawithsand/crypka"

type EncKeyBag struct {
	EncKey crypka.EncKey
	DecKey crypka.DecKey

	BaseBag
}

func (bag *EncKeyBag) EnsureValidSymm(algo crypka.EncSymmAlgo) (err error) {
	if bag.EncKey == nil {
		bag.EncKey, err = algo.GenerateKey(nil, bag.GenerateRNG)
		if err != nil {
			return
		}
	}
	if bag.DecKey == nil {
		bag.DecKey, err = algo.GenerateKey(nil, bag.GenerateRNG)
		if err != nil {
			return
		}
	}
	return
}
