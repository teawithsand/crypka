package crypka

// CounterNonceManager is preallocated slice of specified size, which can be efficiently incremented by one
// in order to produce unique nonces for data encryption.
//
// NOTE: THIS IS NOT CONSTANT TIME!!!
// Be aware that this counter leaks(or may leak) count of chunks encrypted already.
// Usually this is not problem, since attacker knows anyway how many chunks were encrypted.
type CounterNonceManager struct {
	Nonce  []byte
	Unsafe bool
}

func NewNonceCounterManager(sz int, unsafe bool) *CounterNonceManager {
	return &CounterNonceManager{
		Nonce:  make([]byte, sz),
		Unsafe: unsafe,
	}
}

// Increment assigns next unique value to this nonce counter.
// If it's not possible without overflowing or changing nonce size then error is returned.
func (nm CounterNonceManager) NextNonce() (err error) {
	nonce := nm.Nonce
	for i := 0; i < len(nonce); i++ {
		if nonce[i] == 255 && i == len(nonce)-1 {
			if nm.Unsafe {
				for _, j := range nonce {
					nonce[j] = 0
				}
			} else {
				err = ErrTooManyChunksEncrypted
			}
			return
		} else if nonce[i] == 255 {
			nonce[i] = 0
		} else {
			nonce[i]++
			break
		}
	}

	return
}

func (nm CounterNonceManager) GetNonce() []byte {
	return nm.Nonce
}

// Len retuns size of nonce generated by this nonce counter.
func (nm CounterNonceManager) Len() int {
	return len(nm.Nonce)
}