//go:build go1.18
// +build go1.18

package crypkatest

import (
	"fmt"
	"testing"
)

func (tester *KXTester) Fuzz(f *testing.F, method KXFuzzMethod) {
	if method == KXFuzzMethodRandomExchange {
		f.Fuzz(func(t *testing.T, data []byte) {
			var chunks [2][]byte
			var i int
			err := FuzzingNChunks(data, 2, func(data []byte) (err error) {
				chunks[i] = data
				i++
				return
			})
			if err != nil {
				t.Error(err)
				return
			}

			kxp, err := tester.Algo.ParseKXPublic(nil, chunks[0])
			if err != nil {
				return
			}

			kxs, err := tester.Algo.ParseKXSecret(nil, chunks[1])
			if err != nil {
				return
			}

			res := make([]byte, tester.Algo.GetInfo().MaxResLen)
			if len(res) == 0 {
				res = make([]byte, 64)
			}

			err = tester.Algo.PerformExchange(nil, kxp, kxs, res)
			if err != nil {
				return
			}

			for _, b := range res {
				if b != 0 {
					return
				}
			}

			t.Error("found kx pair, which results in zeroed(unmodified?) result slice")
		})
	} else {
		panic(fmt.Errorf("invalid kx fuzz method: %d", method))
	}
}
