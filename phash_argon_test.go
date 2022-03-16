package crypka_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/teawithsand/crypka"
)

const someHash = "$argon2i$v=19$m=120,t=5000,p=2$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt.Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1e"

func TestPHash_Argon2(t *testing.T) {
	t.Run("can_parse", func(t *testing.T) {
		h := crypka.Argon2PasswordHash{}
		err := h.Load(strings.NewReader(someHash))
		if err != nil {
			t.Error(err)
			return
		}

		encoded, err := h.Raw()
		if err != nil {
			t.Error(err)
			return
		}

		oh := crypka.Argon2PasswordHash{}
		err = oh.Load(bytes.NewReader(encoded))
		if err != nil {
			t.Error(err)
			return
		}

		if !reflect.DeepEqual(h, oh) {
			t.Error("expected values to be equal")
			return
		}

		return
	})

	t.Run("can_hash_and_check", func(t *testing.T) {
		h := crypka.Argon2PasswordHasher{
			SaltLength: 16,
			KeyLength:  32,
			Memory:     16 * 1024,
			Time:       1,
			Threads:    1,
		}
		phash, err := h.HashPassword(nil, []byte("asdf"), nil)
		if err != nil {
			t.Error(err)
			return
		}

		err = h.CheckPassword(nil, []byte("asdf"), phash)
		if err != nil {
			t.Error(err)
			return
		}

		err = h.CheckPassword(nil, []byte("fdsa"), phash)
		if !errors.Is(err, crypka.ErrPasswordHashMismatch) {
			t.Error(err)
			return
		}
		return
	})
}

func FuzzPHash_Argon2Load(f *testing.F) {
	h := crypka.Argon2PasswordHash{}

	f.Add([]byte(someHash))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = h.Load(bytes.NewReader(data))
	})
}

/*
// TODO(teawithsand): implement it
func FuzzPHash_Argon2DifferentValuesSameHash(f *testing.F) {
	h := crypka.Argon2PasswordHash{}

	f.Add([]byte(someHash))
	f.Fuzz(func(t *testing.T, a []byte, b []byte) {
		_ = h.Load(bytes.NewReader(data))
	})
}
*/
