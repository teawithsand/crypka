package crypka

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PHCPasswordHash encoded in PHC format
type Argon2PasswordHash struct {
	Name string
	Salt []byte
	Hash []byte

	Version int

	Time    uint32
	Memory  uint32
	Threads uint8
}

func (dh *Argon2PasswordHash) Load(r io.ByteReader) (err error) {
	p := bmcParser{
		R: r,
	}

	h := Argon2PasswordHash{}

	state := 0
	for {
		err = p.Next()
		if errors.Is(err, io.EOF) {
			err = nil
			break
		} else if err != nil {
			return
		}

		if state == 0 {
			h.Name = string(p.Value)
			state = 1
		} else if state == 1 || state == 2 {
			pp := argParser{
				R: bytes.NewReader(p.Value),
			}
			for {
				err = pp.Next()
				if errors.Is(err, io.EOF) {
					err = nil
					break
				} else if err != nil {
					return
				}

				if string(pp.Name) == "v" {
					_, err = fmt.Sscanf(string(pp.Value), "%d", &h.Version)
					if err != nil {
						return
					}
				} else if string(pp.Name) == "m" {
					_, err = fmt.Sscanf(string(pp.Value), "%d", &h.Memory)
					if err != nil {
						return
					}
				} else if string(pp.Name) == "t" {
					_, err = fmt.Sscanf(string(pp.Value), "%d", &h.Time)
					if err != nil {
						return
					}
				} else if string(pp.Name) == "p" {
					_, err = fmt.Sscanf(string(pp.Value), "%d", &h.Threads)
					if err != nil {
						return
					}
				} else {
					// ignore unknown param
				}
			}

			// TODO(teawithsand): check against parsing unknown parametrs
			// TODO(teawithsand): check against parameter regrouping, for now this parser is quite la

			state += 1
		} else if state == 3 {
			var salt []byte
			salt, err = passwordBase64Encoding.DecodeString(string(p.Value))
			if err != nil {
				err = ErrPasswordHashParseFiled
				return
			}

			h.Salt = salt
			state = 4
		} else if state == 4 {
			var hash []byte
			hash, err = passwordBase64Encoding.DecodeString(string(p.Value))
			if err != nil {
				err = ErrPasswordHashParseFiled
				return
			}

			h.Hash = hash
			state = 5
		} else {
			// never called when valid encoding
			err = ErrPasswordHashParseFiled
			return
		}
	}

	if state != 5 {
		err = ErrPasswordHashParseFiled
	} else {
		*dh = h
	}
	return
}

func (h *Argon2PasswordHash) GetAlgo() string {
	return h.Name
}

func (h *Argon2PasswordHash) encodeParams() string {
	return strings.Join([]string{
		fmt.Sprintf("m=%d", h.Memory),
		fmt.Sprintf("t=%d", h.Time),
		fmt.Sprintf("p=%d", h.Threads),
	}, ",")
}

func (h *Argon2PasswordHash) Raw() (res []byte, err error) {
	w := bytes.NewBuffer(nil)
	wr := bmcWriter{w}
	wr.WriteParam(h.Name)
	wr.WriteParam(fmt.Sprintf("v=%d", h.Version))
	wr.WriteParam(h.encodeParams())
	wr.WriteParam(passwordBase64Encoding.EncodeToString(h.Salt))
	wr.WriteParam(passwordBase64Encoding.EncodeToString(h.Hash))

	res = w.Bytes()
	return
}

type Argon2PasswordHasher struct {
	// Defaults to argon2id
	AlgoName string

	SaltLength uint32
	KeyLength  uint32

	Memory  uint32
	Time    uint32
	Threads uint8

	RNG RNG
}

func (h *Argon2PasswordHasher) HashPassword(ctx PasswordHashContext, password, appendTo []byte) (res []byte, err error) {
	res = appendTo

	rng := FallbackContextGetRNG(ctx, h.RNG)

	salt := make([]byte, int(h.SaltLength))
	_, err = io.ReadFull(rng, salt)
	if err != nil {
		return
	}

	name := "argon2id"
	if len(h.AlgoName) > 0 {
		name = h.AlgoName
	}

	rawHash := argon2.IDKey(password, salt, h.Time, h.Memory, h.Threads, h.KeyLength)
	typedHash := Argon2PasswordHash{
		Name:    name,
		Salt:    salt,
		Hash:    rawHash,
		Version: 0x13,
		Time:    h.Time,
		Threads: h.Threads,
		Memory:  h.Memory,
	}

	raw, err := typedHash.Raw()
	if err != nil {
		return
	}

	res = append(res, raw...)
	return
}

func (h *Argon2PasswordHasher) CheckPassword(ctx PasswordHashContext, password, hash []byte) (err error) {
	phash := Argon2PasswordHash{}
	err = phash.Load(bytes.NewReader(hash))
	if err != nil {
		return
	}

	name := "argon2id"
	if len(h.AlgoName) > 0 {
		name = h.AlgoName
	}

	if phash.Name != name || phash.Version != 0x13 {
		err = ErrPasswordHashUnknownAlgo
		return
	}

	if phash.Time != h.Time ||
		phash.Memory != h.Memory ||
		phash.Threads != phash.Threads ||
		len(phash.Salt) != int(h.SaltLength) ||
		len(phash.Hash) != int(h.KeyLength) {
		err = ErrPasswordHashParamMismatch
		return
	}

	rawHash := argon2.IDKey(password, phash.Salt, h.Time, h.Memory, h.Threads, h.KeyLength)
	if !hmac.Equal(rawHash, phash.Hash) {
		err = ErrPasswordHashMismatch
		return
	}

	return
}
