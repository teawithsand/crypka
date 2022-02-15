package crypka

import (
	"bytes"
	"encoding/binary"
	"io"
)

type intEncoding int8

const intEncodingMaxSize = 9

func (e intEncoding) IsValid() bool {
	return e == ByteVar || e == Byte1 || e == Byte2 || e == Byte4 || e == Byte8
}

func (e intEncoding) Size(n uint64) int {
	var arr [intEncodingMaxSize]byte
	switch e {
	case ByteVar:
		s := binary.PutUvarint(arr[:], n)
		return s
	case Byte1:
		if n > (1<<8)-1 {
			return -1
		}
		return 1
	case Byte2:
		if n > (1<<16)-1 {
			return -1
		}
		return 1
	case Byte4:
		if n > (1<<32)-1 {
			return -1
		}
		return 1
	case Byte8:
		if n > (1<<64)-1 {
			return -1
		}
		return 1
	default:
		return -1
	}
}

func (e intEncoding) MaxSize() int {
	switch e {
	case ByteVar:
		return intEncodingMaxSize
	case Byte1:
		return 1
	case Byte2:
		return 2
	case Byte4:
		return 4
	case Byte8:
		return 8
	default:
		return -1
	}
}

func (e intEncoding) EncodeAtStart(buf []byte, n uint64) (sz int) {
	switch e {
	case ByteVar:
		sz = binary.PutUvarint(buf, n)
	case Byte1:
		buf[0] = byte(n)
	case Byte2:
		sz = 2
		binary.BigEndian.PutUint16(buf, uint16(n))
	case Byte4:
		sz = 4
		binary.BigEndian.PutUint32(buf, uint32(n))
	case Byte8:
		sz = 8
		binary.BigEndian.PutUint64(buf, n)
	default:
		sz = -1
	}
	return
}

func (e intEncoding) EncodeAtEnd(buf []byte, n uint64) (sz int) {
	encodedSz := e.Size(n)
	buf = buf[len(buf)-encodedSz:]
	return e.EncodeAtStart(buf, n)
}

func (e intEncoding) AppendToBuf(appendTo []byte, n uint64) (res []byte, sz int) {
	encodedSz := e.Size(n)
	res = appendTo
	for i := 0; i < encodedSz; i++ {
		res = append(res, 0)
	}
	sz = e.EncodeAtEnd(res, n)
	return
}

type byteReaderExt struct {
	R io.Reader
}

func (r byteReaderExt) ReadByte() (b byte, err error) {
	var arr [1]byte

	_, err = io.ReadFull(r.R, arr[:])
	if err != nil {
		return
	}

	b = arr[0]
	return
}

func (e intEncoding) Decode(r io.Reader) (n uint64, err error) {
	var b byte

	var br io.ByteReader
	var ok bool
	if br, ok = r.(io.ByteReader); ok {
	} else {
		br = byteReaderExt{R: r}
	}

	switch e {
	case ByteVar:
		return binary.ReadUvarint(br)
	case Byte1:
		b, err = br.ReadByte()
		if err != nil {
			return
		}
		n = uint64(b)
	case Byte2:
		var arr [2]byte
		_, err = io.ReadFull(r, arr[:])
		if err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(arr[:]))
	case Byte4:
		var arr [4]byte
		_, err = io.ReadFull(r, arr[:])
		if err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint32(arr[:]))
	case Byte8:
		var arr [8]byte
		_, err = io.ReadFull(r, arr[:])
		if err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint64(arr[:]))
	default:
		panic("NIY ERROR HERE INVALID INT ENCODING")
	}
	return
}

func (e intEncoding) DecodeAtStart(buf []byte) (n uint64, sz int, err error) {
	reader := bytes.NewReader(buf)
	n, err = e.Decode(reader)
	sz = len(buf) - reader.Len()
	return
}

const (
	ByteVar intEncoding = 0 //default is variable
	Byte1   intEncoding = 1
	Byte2   intEncoding = 2
	Byte4   intEncoding = 4
	Byte8   intEncoding = 8
)
