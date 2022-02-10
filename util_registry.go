package crypka

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

var ErrNoSuchAlgorithm = errors.New("crypka: No such algorithm")
var ErrInvalidAlgorithmType = errors.New("crypka: Invalid algorithm type")
var ErrInvalidDestinationType = errors.New("crypka: Invalid getter destintation type. Must be pointer to struct or interface")

// Registry for any kind of algorithm.
type Registry interface {
	RegisterAlgo(name string, algo interface{})
	GetAlgo(name string) (algo interface{})
	Lock()

	GetAlgorithmTyped(name string, dstAlgo interface{}) (err error)
}

// defaultRegistry is map of string to interface{}, which contains some features to make it suitable
// for handling algorithms.
type defaultRegistry struct {
	locked   int32
	lock     *sync.Mutex
	contents map[string]interface{}
}

func NewRegistry() Registry {
	return &defaultRegistry{
		contents: map[string]interface{}{},
		lock:     &sync.Mutex{},
	}
}

func (reg *defaultRegistry) RegisterAlgo(name string, algo interface{}) {
	if atomic.LoadInt32(&reg.locked) != 0 {
		panic("register already locked")
	}

	reg.lock.Lock()
	defer reg.lock.Unlock()
	_, ok := reg.contents[name]
	if ok {
		panic(fmt.Errorf("algorithm with name %s is already registered", name))
	}
	reg.contents[name] = algo
}

func (reg *defaultRegistry) GetAlgo(name string) (algo interface{}) {
	locked := atomic.LoadInt32(&reg.locked)
	if locked != 0 {
		return reg.contents[name]
	} else {
		reg.lock.Lock()
		defer reg.lock.Unlock()

		return reg.contents[name]
	}
}

func (reg *defaultRegistry) Lock() {
	reg.lock.Lock()
	atomic.StoreInt32(&reg.locked, 1)
	reg.lock.Unlock()
}

func (reg *defaultRegistry) GetAlgorithmTyped(name string, dstAlgo interface{}) (err error) {
	rawAlgo := reg.GetAlgo(name)
	if rawAlgo == nil {
		err = ErrNoSuchAlgorithm
		return
	}

	dstAlgoValue := reflect.ValueOf(dstAlgo)
	if dstAlgoValue.Kind() != reflect.Ptr {
		err = ErrInvalidDestinationType
		return
	}

	if !reflect.TypeOf(rawAlgo).AssignableTo(dstAlgoValue.Elem().Type()) {
		err = ErrInvalidAlgorithmType
		return
	}

	dstAlgoValue.Elem().Set(reflect.ValueOf(rawAlgo))
	return
}
