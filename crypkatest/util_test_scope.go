package crypkatest

import (
	"crypto/rand"

	"github.com/teawithsand/crypka"
)

type BaseBag struct {
	Context     crypka.KeyGenerationContext
	GenerateRNG crypka.RNG
}

var defaultTestScopeUtil = &TestScopeUtil{}

type TestScopeUtil struct {
	ChunkRunnerConfig ChunkRunnerConfig
	TestRNGFactory    func() crypka.RNG
}

// Note: use test scope instead in any newer implementation.
// Consider this function deprecated at the moment of it's creation.
func (tsu *TestScopeUtil) GetTestRNG() crypka.RNG {
	if tsu == nil {
		tsu = defaultTestScopeUtil
	}

	if tsu.TestRNGFactory == nil {
		return rand.Reader
	}
	return tsu.TestRNGFactory()
}

func (tsu *TestScopeUtil) GetTestScope() *TestScope {
	if tsu == nil {
		tsu = defaultTestScopeUtil
	}

	var rng crypka.RNG
	if tsu.TestRNGFactory == nil {
		rng = rand.Reader
	} else {
		rng = tsu.TestRNGFactory()
	}

	return &TestScope{
		InnerRNG:          rng,
		ChunkRunnerConfig: tsu.ChunkRunnerConfig,
	}
}

type TestScope struct {
	ChunkRunnerConfig ChunkRunnerConfig
	InnerRNG          crypka.RNG // Inner prefix, since GetRNG should be used instead.
}

func (scope *TestScope) GetRNG() crypka.RNG {
	return scope.InnerRNG
}

func (scope *TestScope) GetBaseBag() BaseBag {
	return BaseBag{
		Context:     nil,
		GenerateRNG: scope.InnerRNG,
	}
}

func (scope *TestScope) GetChunkRunner() *ChunkRunner {
	return &ChunkRunner{
		ChunkRunnerConfig: scope.ChunkRunnerConfig,
		RNG:               scope.InnerRNG,
	}
}
