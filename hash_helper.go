package crypka

import "encoding/binary"

func NewHashableHelper(hw HashableWriter) *HashableHelper {
	return &HashableHelper{
		HashableWriter: hw,
	}
}

// Provides a few extension functions, which HashableWriter does not have, but are useful when implementing
type HashableHelper struct {
	HashableWriter
}

func (util *HashableHelper) WriteStruct(writer func(hh *HashableHelper) (err error)) (err error) {
	err = util.EnterStruct()
	if err != nil {
		return
	}

	err = writer(util)
	if err != nil {
		return
	}

	err = util.ExitStruct()
	if err != nil {
		return
	}

	return
}

func (util *HashableHelper) WriteSlice(length int, writer func(hh *HashableHelper) (err error)) (err error) {
	err = util.EnterSlice(length)
	if err != nil {
		return
	}

	err = writer(util)
	if err != nil {
		return
	}

	err = util.ExitSlice()
	if err != nil {
		return
	}

	return
}

func (util *HashableHelper) WriteByteSlice(data []byte) (err error) {
	err = util.WriteVarBytes(data)
	if err != nil {
		return
	}
	return
}

func (util *HashableHelper) WriteString(data string) (err error) {
	err = util.WriteVarBytes([]byte(data))
	if err != nil {
		return
	}
	return
}

func (util *HashableHelper) WriteUint64(v uint64) (err error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	err = util.HashableWriter.WriteConstBytes(buf[:])
	return
}

func (util *HashableHelper) WriteUint32(v uint32) (err error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	err = util.HashableWriter.WriteConstBytes(buf[:])
	return
}

func (util *HashableHelper) WriteUint16(v uint16) (err error) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	err = util.HashableWriter.WriteConstBytes(buf[:])
	return
}

func (util *HashableHelper) WriteUint8(v uint8) (err error) {
	err = util.HashableWriter.WriteConstBytes([]byte{v})
	return
}

func (util *HashableHelper) WriteInt(v int) (err error) {
	return util.WriteInt64(int64(v))
}

func (util *HashableHelper) WriteInt64(v int64) (err error) {
	return util.WriteUint64(uint64(v))
}

func (util *HashableHelper) WriteInt32(v int32) (err error) {
	return util.WriteUint32(uint32(v))
}

func (util *HashableHelper) WriteInt16(v int16) (err error) {
	return util.WriteUint16(uint16(v))
}

func (util *HashableHelper) WriteInt8(v int8) (err error) {
	return util.WriteUint8(uint8(v))
}
