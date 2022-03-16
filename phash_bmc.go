package crypka

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
)

// Parsing/encoding hashes here refers to (Binary) Modular Crypt Format - binary support is NIY
// https://github.com/ademarre/binary-mcf

const base64Alphabeth = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var passwordBase64Encoding = base64.NewEncoding(base64Alphabeth).WithPadding(base64.NoPadding)

func parseAlgo(encoded []byte) (algo []byte, err error) {
	if len(encoded) == 0 {
		err = ErrPasswordHashParseFiled
		return
	}
	if encoded[0] != '$' {
		err = ErrPasswordHashParseFiled
		return
	}

	i := bytes.IndexByte(encoded[1:], byte('$'))
	if i < 0 {
		err = ErrPasswordHashParseFiled
		return
	}

	algo = encoded[1:i]
	return
}

type bmcParser struct {
	R           io.ByteReader
	Value       []byte
	state       int
	cachedError error
}

func (p *bmcParser) Get() []byte {
	return p.Value
}

func (p *bmcParser) Next() (err error) {
	if p.cachedError != nil {
		err = p.cachedError
		return
	}
	p.Value = nil

	for {
		var b byte
		b, err = p.R.ReadByte()
		if len(p.Value) > 0 && err != nil {
			p.cachedError = err
			err = nil
			return
		} else if err != nil {
			return
		}

		if p.state == 0 {
			if b != '$' {
				err = ErrPasswordHashParseFiled
				return
			}

			p.state = 1
		} else if p.state == 1 {
			if b == '$' {
				break
			} else {
				p.Value = append(p.Value, b)
			}
		}
	}

	return
}

type argParser struct {
	R           io.ByteReader
	Name        []byte
	Value       []byte
	cachedError error
}

func (p *argParser) Get() []byte {
	return p.Value
}

func (p *argParser) Next() (err error) {
	if p.cachedError != nil {
		err = p.cachedError
		return
	}

	p.Value = nil
	p.Name = nil

	state := 0
	for {
		var b byte
		b, err = p.R.ReadByte()
		if errors.Is(err, io.EOF) && state == 0 {
			err = io.ErrUnexpectedEOF
		}

		if len(p.Value) > 0 && err != nil {
			p.cachedError = err
			err = nil
			return
		} else if err != nil {
			return
		}

		if state == 0 {
			if b == '=' {
				state = 1
			} else {
				p.Name = append(p.Name, b)
			}
		} else if state == 1 {
			if b == ',' {
				state = 0
				break
			}
			p.Value = append(p.Value, b)
		}
	}

	return
}

type bmcWriter struct {
	W io.Writer
}

func (w *bmcWriter) WriteParam(p string) (err error) {
	_, err = w.W.Write([]byte("$"))
	if err != nil {
		return
	}
	_, err = w.W.Write([]byte(p))
	if err != nil {
		return
	}

	return
}

type paramWriter struct {
	W          io.Writer
	isNotFirst bool
}

func (w *paramWriter) WriteParam(p string) (err error) {
	if !w.isNotFirst {
		w.isNotFirst = true
	} else {
		_, err = w.W.Write([]byte(","))
		if err != nil {
			return
		}
	}
	_, err = w.W.Write([]byte(p))
	if err != nil {
		return
	}

	return
}
