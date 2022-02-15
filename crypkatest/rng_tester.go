package crypkatest

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"io"
	"testing"

	"github.com/teawithsand/crypka"
)

type zeroRNG struct{}

func (r *zeroRNG) Read(buf []byte) (sz int, err error) {
	for _, i := range buf {
		buf[i] = 0
	}
	sz = len(buf)
	return
}

var DefaultRNGChunkRunnerConfig = ChunkRunnerConfig{
	DifferentBuffersPresets: [][2][][]byte{
		{
			RNGReadBuffers(&zeroRNG{}, 1, 1, 1),
			RNGReadBuffers(&zeroRNG{}, 3),
		},
		{
			RNGReadBuffers(&zeroRNG{}, 0, 4, 5),
			RNGReadBuffers(&zeroRNG{}, 3, 3, 3),
		},
		{
			RNGReadBuffers(&zeroRNG{}, 1024, 1024*2-1, 1),
			RNGReadBuffers(&zeroRNG{}, 1024, 1024, 1024),
		},
	},
}

type RNGTester struct {
	Algo crypka.RNGAlgo
	TestScopeUtil

	NotMarshalable bool
}

func (tester *RNGTester) init() {
	if tester.TestScopeUtil.ChunkRunnerConfig.IsEmpty() {
		tester.TestScopeUtil.ChunkRunnerConfig = DefaultRNGChunkRunnerConfig
	}
}

func (tester RNGTester) Test(t *testing.T) {
	tester.init()

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

		const readDataSize = 16
		if tester.Algo.GetInfo().MaxGeneratedBytes != 0 && tester.Algo.GetInfo().MaxGeneratedBytes <= readDataSize {
			t.Error("This test does not support RNGs that can generate less than", readDataSize, "bytes")
			return
		}

		var b1 [readDataSize]byte
		_, err = io.ReadFull(rng, b1[:])
		if err != nil {
			t.Error(err)
			return
		}

		var b2 [readDataSize]byte
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

			const readDataSize = 1024
			if tester.Algo.GetInfo().MaxGeneratedBytes != 0 && tester.Algo.GetInfo().MaxGeneratedBytes <= readDataSize {
				t.Error("This test does not support RNGs that can generate less than", readDataSize, "bytes")
				return
			}

			var buf1 [readDataSize]byte
			_, err = io.ReadFull(rng1, buf1[:])
			if err != nil {
				t.Error(err)
				return
			}

			var buf2 [readDataSize]byte
			_, err = io.ReadFull(rng2, buf2[:])
			if err != nil {
				t.Error(err)
				return
			}

			if !bytes.Equal(buf1[:], buf2[:]) {
				t.Error("expected same seed to yield same data")
			}
		})

		// TODO(teawithsand): make this test into fuzzer
		t.Run("same_seed_different_read_sizes_give_same_data", func(t *testing.T) {
			scope := tester.GetTestScope()

			seed, err := crypka.GenerateReasonableRNGSeed(scope.GetRNG(), tester.Algo.GetInfo())
			if err != nil {
				t.Error(err)
				return
			}

			err = scope.GetChunkRunner().runWithDifferentChunks(func(lhs, rhs [][]byte) (err error) {
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

				sumLhsLength := 0
				for _, l := range lhs {
					sumLhsLength += len(l)
				}

				sumRhsLength := 0
				for _, r := range rhs {
					sumRhsLength += len(r)
				}

				readLimit := sumLhsLength
				if sumRhsLength < sumLhsLength {
					readLimit = sumRhsLength
				}

				h1 := sha1.New()

				{
					readBytes := 0
					for _, c := range lhs {
						if readBytes == readLimit {
							break
						}

						if readBytes+len(c) > readLimit {
							c = c[:readLimit-readBytes]
						}

						_, err = io.ReadFull(rng1, c)
						if err != nil {
							return
						}

						readBytes += len(c)

						h1.Write(c)
					}
				}

				h2 := sha1.New()
				{
					readBytes := 0
					for _, c := range rhs {
						if readBytes == readLimit {
							break
						}

						if readBytes+len(c) > readLimit {
							c = c[:readLimit-readBytes]
						}

						_, err = io.ReadFull(rng2, c)
						if err != nil {
							return
						}

						readBytes += len(c)

						h2.Write(c)
					}
				}

				if !bytes.Equal(h1.Sum(nil), h2.Sum(nil)) {
					err = errors.New("different read sizes yielded diffrent data")
					return
				}

				return
			})

			if err != nil {
				t.Error(err)
			}
		})
	}
}

func (tester *RNGTester) Benchmark(b *testing.B) {
	tester.init()

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
