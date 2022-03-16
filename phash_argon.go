package crypka

import (
	"bytes"
	"fmt"
	"strings"
)

// PHCPasswordHash encoded in PHC format
type Argon2PasswordHash struct {
	Name            string
	Salt            []byte
	Hash            []byte
	Version         int
	TimeCost        int
	MemoryCost      int32
	ParallelismCost int32
}

func (h *Argon2PasswordHash) GetAlgo() string {
	return h.Name
}

func (h *Argon2PasswordHash) encodeParams() string {
	return strings.Join([]string{
		fmt.Sprintf("v=%d", h.Version),
		fmt.Sprintf("m=%d", h.MemoryCost),
		fmt.Sprintf("t=%d", h.TimeCost),
		fmt.Sprintf("p=%d", h.ParallelismCost),
	}, ",")
}

func (h *Argon2PasswordHash) Raw() (res []byte) {
	w := bytes.NewBuffer(nil)
	wr := bmcWriter{w}
	wr.WriteParam(h.Name)
	wr.WriteParam(h.encodeParams())
	wr.WriteParam(passwordBase64Encoding.EncodeToString(h.Salt))
	wr.WriteParam(passwordBase64Encoding.EncodeToString(h.Hash))

	res = w.Bytes()
	return
}
