package crypka

import (
	"encoding/binary"
	"io"
)

// Makes simple Writer into HashableWriter.
// It's secure until HashWriter's method are used properly and this struct is the only owner of writer given.
type DefaultHashableWriter struct {
	W io.Writer
}

func (wr *DefaultHashableWriter) Finalize() (err error) {
	return
}

func (wr *DefaultHashableWriter) EnterStruct() (err error) {
	return
}
func (wr *DefaultHashableWriter) ExitStruct() (err error) {
	return
}

func (wr *DefaultHashableWriter) EnterSlice(length int) (err error) {
	if length < 0 {
		panic("crypka: length < 0")
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(length))

	_, err = wr.W.Write(buf[:])
	if err != nil {
		return
	}

	return
}

func (wr *DefaultHashableWriter) ExitSlice() (err error) {
	return
}

func (wr *DefaultHashableWriter) WriteVarBytes(data []byte) (err error) {
	length := uint64(len(data))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], length)

	_, err = wr.W.Write(buf[:])
	if err != nil {
		return
	}

	_, err = wr.W.Write(data)
	if err != nil {
		return
	}

	return
}

func (wr *DefaultHashableWriter) WriteConstBytes(data []byte) (err error) {
	_, err = wr.W.Write(data)
	if err != nil {
		return
	}
	return
}

// HashHashable writes hashable into writer given using default HashableWriter.
func HashHashable(data Hashable, w io.Writer) (err error) {
	hw := &DefaultHashableWriter{
		W: w,
	}
	err = data.HashSelf(hw)
	if err != nil {
		return
	}
	err = hw.Finalize()
	if err != nil {
		return
	}
	return
}
