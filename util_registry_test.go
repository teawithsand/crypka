package crypka_test

import (
	"io"
	"testing"

	"github.com/teawithsand/crypka"
)

type algo1 struct {
}

func (*algo1) Read([]byte) (int, error) {
	return 0, nil
}

type algo2 struct{}

func InitTestRegistry() crypka.Registry {
	registry := crypka.NewRegistry()

	registry.RegisterAlgo("a1", &algo1{})
	registry.RegisterAlgo("a2", &algo2{})

	return registry
}

func TestRegistry_GetAlgorithmTyped_Ok(t *testing.T) {
	registry := InitTestRegistry()

	var res io.Reader
	err := registry.GetAlgorithmTyped("a1", &res)
	if err != nil {
		t.Error(err)
		return
	}

	_ = res.(*algo1)

}

func TestRegistry_GetAlgorithmTyped_ErrorWhenInvalidType(t *testing.T) {
	registry := InitTestRegistry()

	var res io.Writer
	err := registry.GetAlgorithmTyped("a1", &res)
	if err == nil {
		t.Error("Expected error")
		return
	}
}
