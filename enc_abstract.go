package crypka

type EncKey interface {
	MakeEncryptor(ctx KeyContext) (Encryptor, error)
}

type DecKey interface {
	MakeDecryptor(ctx KeyContext) (Decryptor, error)
}

// ENCRYPTOR STUFF //

// Defines relations between subsequent call to Encrypt/Decrypt functions.
// See specific types for more details.
type EncType uint8

const (
	// Block encryption encrypts(decrypts) each block atomically.
	// Blocks are independent of each other.
	//
	// Note: this should not be mistaken with block encryption from crypto world in general ie. fixed block size.
	// This one is more like AEAD encryption(think of box/sealedbox from nacl)
	EncTypeBlock EncType = 1

	// This kind of encryption requires that chunks passed for decryption are passed in same order(it MAY NOT be checked however)
	// that they were passed for encryption.
	//
	// Also no slicing is allowed. Each chunk yielded from encrypt must be passed in same and unmodified form to decrypt.
	EncTypeChain EncType = 2

	// It's just like EncTypeChain, but allows slicing. Passing partial chunks to decrypt is allowed.
	EncTypeStream EncType = 3
)

// Note: this structure contains only basic information about encryption algorithm.
// In particular kind and if it requires finalization.
//
// Note #2: this structure should contain only data, which is required to run encryption properly.
//
// For more information about specified encryption scheme algorithm should be used.
type EncInfo struct {
	RequiresFinalization bool
	EncType              EncType
}

// Note: I've omitted decryption finalization, which requires last chunk(yielded by finalize)
// to be passed separately to decryptor's finalize.
// From my experience using this makes more bugs and adds more complexity to library than it's worth, especially
// that in real world environment it's hardly ever the case.

type Encryptor interface {
	GetEncInfo() EncInfo

	Encrypt(in, appendTo []byte) (res []byte, err error)
	Finalize(appendTo []byte) (res []byte, err error)
}

type Decryptor interface {
	GetEncInfo() EncInfo

	Decrypt(in, appendTo []byte) (res []byte, err error)
	Finalize() (err error)
}

// Note: rest of bits of this value is reserved for future use.
// They must not be used by any implementation.
type EncAuthMode uint32

const NotAuthenticatedEncAuthMode EncAuthMode = 0

func bool2int(to bool) uint8 {
	if to {
		return 1
	} else {
		return 0
	}
}

func (eam *EncAuthMode) IsZero() bool {
	return eam == nil || *eam == 0
}

func (eam *EncAuthMode) setBit(to bool, nth int) {
	(*eam) |= EncAuthMode(bool2int(to)) << nth
}

func (eam *EncAuthMode) getBit(nth int) bool {
	return eam != nil && *eam&(1<<nth) > 0
}

// Returns true if decryptor will never yield data that differs from originally encrypted.
func (eam *EncAuthMode) IsEagerAuthenticated() bool {
	return eam.getBit(0)
}

func (eam *EncAuthMode) SetEagerAuthenticated(to bool) {
	eam.setBit(to, 0)
}

// Returns true, if decryptor will always detect changes made to ciphertext during finalization.
//
// Note: this does not apply to block encryptors,
// since they by their nature are not finalizable, so according to above def, they should have it set to true.
func (eam *EncAuthMode) IsFinalizeAuthetnicated() bool {
	return eam.getBit(1)
}
func (eam *EncAuthMode) SetFinalizeAuthetnicated(to bool) {
	eam.setBit(to, 1)
}

// Retruns true, if decryptor will always detect if stream/chain encryption was truncated.
//
// Note: this does not apply to block encryptors.
// They are never trunc authenticated, due to how they work.
func (eam *EncAuthMode) IsTruncAuthenticated() bool {
	return eam.getBit(2)
}

func (eam *EncAuthMode) SetTruncAuthenticated(to bool) {
	eam.setBit(to, 2)
}

type EncAlgoInfo struct {
	BaseAlgorithmInfo
	EncInfo

	AuthMode EncAuthMode
}

type EncAlgo interface {
	GetInfo() EncAlgoInfo
}

// ASYMMETRIC STUFF HERE //

type EncAsymAlgo interface {
	EncAlgo
	EncAsymKeygen
	EncAsymKeyParser
}

type EncAsymKeygen interface {
	GenerateKeyPair(ctx KeyGenerationContext, rng RNG) (EncKey, DecKey, error)
}

type EncAsymKeyParser interface {
	ParseEncKey(ctx KeyParseContext, data []byte) (EncKey, error)
	ParseDecKey(ctx KeyParseContext, data []byte) (DecKey, error)
}

// SYMMETRIC STUFF HERE //

type EncSymmAlgo interface {
	EncAlgo
	EncSymmKeygen
	EncSymmKeyParser
}

type EncSymmKeygen interface {
	GenerateKey(ctx KeyGenerationContext, rng RNG) (EncSymmKey, error)
}

type EncSymmKeyParser interface {
	ParseSymmEncKey(ctx KeyParseContext, data []byte) (EncSymmKey, error)
}

type EncSymmKey interface {
	EncKey
	DecKey
}
