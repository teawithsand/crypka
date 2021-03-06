package crypka

import (
	"crypto/rand"
)

type KeyContext = *Context
type KeyGenerationContext = *Context
type KeyParseContext = *Context
type RNGGenerationContext = *Context
type HashContext = *Context
type PasswordHashContext = *Context

type AnyContext = *Context

type Context struct {
	RNG              RNG
	SetInsecureTaint bool
}

func MakeDefaultContext() *Context {
	return &Context{
		RNG: rand.Reader,
	}
}

func ContextGetRNG(ctx *Context) RNG {
	if ctx == nil || ctx.RNG == nil {
		return rand.Reader
	}
	return ctx.RNG
}

// Returns given RNG or one from context in case given one was nil.
// Returns default RNG in case provided one was not set.
func FallbackContextGetRNG(ctx *Context, rng RNG) RNG {
	if rng != nil {
		if rng == nil {
			return rand.Reader
		}
		return rng
	}

	return ContextGetRNG(ctx)
}
