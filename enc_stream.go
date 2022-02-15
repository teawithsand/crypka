package crypka

// Implements algorithm, which handles streamming encryption in crypka's format.
type CPKStreamSymmEncAlgo struct {
	EncSymmAlgo
}

func (algo *CPKStreamSymmEncAlgo) GetInfo() EncAlgoInfo {
	info := algo.EncSymmAlgo.GetInfo()
	info.EncType = EncTypeStream

	// TODO(teawithsand): patch authentication info here

	return info
}
