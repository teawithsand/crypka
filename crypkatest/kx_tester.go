package crypkatest

import (
	"bytes"
	"testing"

	"github.com/teawithsand/crypka"
)

type KXFuzzMethod int

const (
	KXFuzzMethodRandomExchange KXFuzzMethod = 1
)

type KXTester struct {
	Algo crypka.KXAlgo
	TestScopeUtil

	NotMarshalable bool
}

func (tester *KXTester) init() {
}

func (tester KXTester) Test(t *testing.T) {
	tester.init()

	t.Run("kx_key_match", func(t *testing.T) {
		scope := tester.GetTestScope()

		p1, s1, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
		if err != nil {
			t.Error(err)
			return
		}

		p2, s2, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
		if err != nil {
			t.Error(err)
			return
		}

		res1 := make([]byte, tester.Algo.GetInfo().MaxResLen)
		if len(res1) == 0 {
			res1 = make([]byte, 64)
		}

		err = tester.Algo.PerformExchange(nil, p2, s1, res1)
		if err != nil {
			t.Error(err)
			return
		}

		res2 := make([]byte, tester.Algo.GetInfo().MaxResLen)
		if len(res2) == 0 {
			res2 = make([]byte, 64)
		}

		err = tester.Algo.PerformExchange(nil, p1, s2, res2)
		if err != nil {
			t.Error(err)
			return
		}

		if !bytes.Equal(res1, res2) {
			t.Error("kx filed, mixing secret one and public two is not equal to secret two and public one")
			return
		}
	})

	t.Run("kx_key_differ", func(t *testing.T) {
		scope := tester.GetTestScope()

		var res1 []byte
		{
			_, s1, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
			if err != nil {
				t.Error(err)
				return
			}

			p2, _, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
			if err != nil {
				t.Error(err)
				return
			}

			res1 = make([]byte, tester.Algo.GetInfo().MaxResLen)
			if len(res1) == 0 {
				res1 = make([]byte, 64)
			}

			err = tester.Algo.PerformExchange(nil, p2, s1, res1)
			if err != nil {
				t.Error(err)
				return
			}
		}

		var res2 []byte
		{
			_, s1, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
			if err != nil {
				t.Error(err)
				return
			}

			p2, _, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
			if err != nil {
				t.Error(err)
				return
			}

			res2 = make([]byte, tester.Algo.GetInfo().MaxResLen)
			if len(res1) == 0 {
				res2 = make([]byte, 64)
			}

			err = tester.Algo.PerformExchange(nil, p2, s1, res2)
			if err != nil {
				t.Error(err)
				return
			}
		}

		if bytes.Equal(res1, res2) {
			t.Error("two rng generated key exchanges returned very same output")
			return
		}
	})

	if !tester.NotMarshalable {
		t.Run("can_marshal_kx_public_secret_pair", func(t *testing.T) {
			scope := tester.GetTestScope()

			p1, _, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
			if err != nil {
				t.Error(err)
				return
			}

			_, s2, err := tester.Algo.GenerateKXPair(nil, scope.GetRNG())
			if err != nil {
				t.Error(err)
				return
			}

			res1 := make([]byte, tester.Algo.GetInfo().MaxResLen)
			if len(res1) == 0 {
				res1 = make([]byte, 64)
			}

			err = tester.Algo.PerformExchange(nil, p1, s2, res1)
			if err != nil {
				t.Error(err)
				return
			}

			ms2, err := crypka.MarshalKeyToSlice(s2)
			if err != nil {
				t.Error(err)
				return
			}
			mp1, err := crypka.MarshalKeyToSlice(p1)
			if err != nil {
				t.Error(err)
				return
			}

			ps2, err := tester.Algo.ParseKXSecret(nil, ms2)
			if err != nil {
				t.Error(err)
				return
			}

			pp1, err := tester.Algo.ParseKXPublic(nil, mp1)
			if err != nil {
				t.Error(err)
				return
			}

			res2 := make([]byte, tester.Algo.GetInfo().MaxResLen)
			if len(res2) == 0 {
				res2 = make([]byte, 64)
			}

			err = tester.Algo.PerformExchange(nil, pp1, ps2, res2)
			if err != nil {
				t.Error(err)
				return
			}

			if !bytes.Equal(res1, res2) {
				t.Error("kx of marshaled keys is not equal to kx of raw keys")
				return
			}
		})
	}
}
