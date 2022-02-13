package crypkatest

var DefaultEncChunkRunnerConfig = ChunkRunnerConfig{
	Sizes: [][]int{
		{}, {1}, {2}, {1024},
		{1023, 1025},
		{1024 * 4},
	},
}
