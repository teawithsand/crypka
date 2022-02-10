package crypkatest

import "crypto/rand"

var DefaultSignChunkRunner = &ChunkRunner{
	Sizes: [][]int{
		{}, {1}, {2}, {1024},
		{1023, 1025},
		{1024 * 4},
	},
	RNG: rand.Reader,
}
