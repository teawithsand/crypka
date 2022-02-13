package crypkatest

import (
	"bytes"
	"io"
	"testing"

	"github.com/teawithsand/crypka"
)

type RNGTester struct {
	Algo crypka.RNGAlgo
	TestScopeUtil

	NotMarshalable bool
}

func (tester RNGTester) Test(t *testing.T) {
	t.Run("rng_works_simple", func(t *testing.T) {
		scope := tester.GetTestScope()

		seed, err := crypka.GenerateReasonableRNGSeed(scope.GetRNG(), tester.Algo.GetInfo())
		if err != nil {
			t.Error(err)
			return
		}

		rng, err := tester.Algo.MakeRng(nil, seed)
		if err != nil {
			t.Error(err)
			return
		}

		var b1 [16]byte
		_, err = io.ReadFull(rng, b1[:])
		if err != nil {
			t.Error(err)
			return
		}

		var b2 [16]byte
		_, err = io.ReadFull(rng, b2[:])
		if err != nil {
			t.Error(err)
			return
		}

		if bytes.Equal(b1[:], b2[:]) {
			t.Error("expected rng read data to differ")
		}
	})

	if tester.Algo.GetInfo().RNGType == crypka.SeedRNGType {
		t.Run("same_seed_gives_same_data", func(t *testing.T) {
			scope := tester.GetTestScope()

			seed, err := crypka.GenerateReasonableRNGSeed(scope.GetRNG(), tester.Algo.GetInfo())
			if err != nil {
				t.Error(err)
				return
			}

			rng1, err := tester.Algo.MakeRng(nil, seed)
			if err != nil {
				t.Error(err)
				return
			}

			rng2, err := tester.Algo.MakeRng(nil, seed)
			if err != nil {
				t.Error(err)
				return
			}

			var buf1 [1024]byte
			_, err = io.ReadFull(rng1, buf1[:])
			if err != nil {
				t.Error(err)
				return
			}

			var buf2 [1024]byte
			_, err = io.ReadFull(rng2, buf2[:])
			if err != nil {
				t.Error(err)
				return
			}

			if !bytes.Equal(buf1[:], buf2[:]) {
				t.Error("expected same seed to yield same data")
			}
		})
	}
}

func (tester *RNGTester) Benchmark(b *testing.B) {
	rngReadTest := func(sz int) func(b *testing.B) {
		return func(b *testing.B) {

			scope := tester.GetTestScope()
			buf := make([]byte, sz)
			_, err := io.ReadFull(scope.GetRNG(), buf)
			if err != nil {
				b.Error(err)
				return
			}

			seed, err := crypka.GenerateReasonableRNGSeed(scope.GetRNG(), tester.Algo.GetInfo())
			if err != nil {
				b.Error(err)
				return
			}

			rng, err := tester.Algo.MakeRng(nil, seed)
			if err != nil {
				b.Error(err)
				return
			}

			b.SetBytes(int64(sz))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err = io.ReadFull(rng, buf)
				if err != nil {
					b.Error(err)
					return
				}
			}
		}
	}
	b.Run("rng_read_32", rngReadTest(32))
	b.Run("rng_read_64", rngReadTest(32))
	b.Run("rng_read_1024", rngReadTest(1024))
	b.Run("rng_read_4096", rngReadTest(4096))
}
