package crypka_test

import (
	"bytes"
	"crypto"
	"reflect"
	"testing"

	_ "crypto/md5" // registers MD5

	"github.com/teawithsand/crypka"
)

func DoTestStructHasher(t *testing.T, sh crypka.StructHasher) {
	type t1 struct {
		A int32
	}
	type t2 struct {
		A int32
		B int32
	}
	type t3 struct {
		A int32 `shash:"1"`
		B int32
		C int32 `shash:"3"`
	}
	type t3Prim struct {
		A int32 `shash:"3"`
		B int32
		C int32 `shash:"1"`
	}
	type t4 struct {
		Bytes     []byte
		IntSlice  []int
		StringOne string
		StringTwo string
		ByteArray [2]byte
		IntArray  [2]int

		T1Slice []t1
		T1Array [2]t1
	}
	cases := [][2]interface{}{
		{
			t1{
				A: 32,
			},
			t1{
				A: 32,
			},
		},
		{
			t1{
				A: 32,
			},
			t1{
				A: 42,
			},
		},
		{
			&t3{
				A: 21,
				B: 22,
				C: 23,
			},
			&t3{
				A: 21,
				B: 22,
				C: 23,
			},
		},
		{
			&t4{
				Bytes:     []byte{1, 2, 3, 4},
				IntSlice:  []int{1, 2, 3, 4},
				StringOne: "fdsa",
				StringTwo: "asdf",
				ByteArray: [2]byte{1, 2},
				IntArray:  [2]int{1, 2},
				T1Slice: []t1{
					{A: 2},
					{A: 3},
					{A: 4},
					{A: 8},
				},
				T1Array: [2]t1{
					{A: 2},
					{A: 3},
				},
			},
			&t4{
				Bytes:     []byte{1, 2, 3, 4},
				IntSlice:  []int{1, 2, 3, 4},
				StringOne: "fdsa",
				StringTwo: "asdf",
				ByteArray: [2]byte{1, 2},
				IntArray:  [2]int{1, 2},
				T1Slice: []t1{
					{A: 2},
					{A: 3},
					{A: 4},
					{A: 8},
				},
				T1Array: [2]t1{
					{A: 2},
					{A: 3},
				},
			},
		},
		// string diff
		{
			&t4{
				StringTwo: "fdsa",
			},
			&t4{
				StringTwo: "asdf",
			},
		},
		// string aliasing diff
		{
			&t4{
				StringOne: "a",
				StringTwo: "sdf",
			},
			&t4{
				StringTwo: "asdf",
			},
		},
		{
			t3{
				A: 1,
				B: 2,
				C: 3,
			},
			t3Prim{
				A: 1,
				B: 2,
				C: 3,
			},
		},
	}

	t.Run("matches_result_of_deep_equals", func(t *testing.T) {
		for _, c := range cases {
			lhs, rhs := c[0], c[1]

			refEq := reflect.DeepEqual(lhs, rhs)

			lhsHash, err := sh.HashStruct(nil, lhs)
			if err != nil {
				t.Error(err)
				return
			}

			rhsHash, err := sh.HashStruct(nil, rhs)
			if err != nil {
				t.Error(err)
				return
			}

			hashEq := bytes.Equal(lhsHash, rhsHash)

			if refEq != hashEq {
				t.Error("hashes equals but values not equal or vice versa")
				return
			}
		}
	})
}

func Test_StructHasherImpl_WithMD5(t *testing.T) {
	algo := crypka.HashSignAlgorithm{
		Hash: crypto.MD5,
	}
	sk, err := algo.GenerateKey(nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	sh := &crypka.StructHasherImpl{
		SigningKey: sk,
		Writer:     &crypka.DefaultStructHashWriter{},
	}
	DoTestStructHasher(t, sh)
}
