package crypka

import (
	"crypto/rand"
	"io"
)

type KeyContext = *Context
type KeyGenerationContext = *Context
type KeyParseContext = *Context
type RNGGenerationContext = *Context

type AnyContext = *Context

type Context struct {
	RNG              io.Reader
	SetInsecureTaint bool
}

func MakeDefaultContext() *Context {
	return &Context{
		RNG: rand.Reader,
	}
}

func ContextGetRNG(ctx *Context) io.Reader {
	if ctx == nil || ctx.RNG == nil {
		return rand.Reader
	}
	return ctx.RNG
}
