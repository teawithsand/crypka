package crypka_test

import (
	"fmt"
	"testing"

	"github.com/teawithsand/crypka"
)

func TestNonceCounter_NonceUnique(t *testing.T) {
	nc := crypka.NewNonceCounterManager(2, false)
	aggregated := make(map[[2]byte]struct{})
	i := int64(0)

	for {
		var arr [2]byte
		copy(arr[:], nc.GetNonce()[:])

		_, ok := aggregated[arr]
		if ok {
			t.Error("Counter value found twice!")
			return
		}
		aggregated[arr] = struct{}{}

		err := nc.NextNonce()
		if err != nil {
			break
		}

		i++
	}

	if i != 0xffff {
		t.Error(fmt.Sprintf("Invalid i value: %d; expected %d", i, 0xffff))
		return
	}
}

func TestNonceCounter_FailsWhenTooManyNonces(t *testing.T) {
	nc := crypka.NewNonceCounterManager(2, false)
	for {
		err := nc.NextNonce()
		if err != nil {
			break
		}
	}
}

func BenchmarkNonceCounterIncrement(b *testing.B) {
	for i := 16; i <= 24; i += 4 {
		b.Run(fmt.Sprintf("NonceCounter: %d", i), func(b *testing.B) {
			nc := crypka.NewNonceCounterManager(i, false)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := nc.NextNonce()
				if err != nil {
					// note: range from 16 is so big that error should never happen
					b.Error(err)
				}
			}
		})
	}
}
