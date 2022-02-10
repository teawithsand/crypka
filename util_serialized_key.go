package crypka

type SerializedKeyType uint8

type SerializedKey struct {
	Algo string
	Type SerializedKeyType
	Data []byte
}
