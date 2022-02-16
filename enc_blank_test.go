package crypka_test

import (
	"testing"

	"github.com/teawithsand/crypka"
	"github.com/teawithsand/crypka/crypkatest"
)

func TestEnc_Blank(t *testing.T) {
	algo := &crypka.BlankEncSymmAlgo{}
	tester := crypkatest.EncSymmTester{
		Algo:    algo,
		IsBlank: true,
	}
	tester.Test(t)
}
