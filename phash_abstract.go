package crypka

type PasswordHashOptions struct {
	Password []byte
	Salt     []byte
}

// PasswordHasher are special kind of hashes.
// Rather than stream data, they accept constant-sized data and yield hash of it.
type PasswordHasher interface {
	HashPassword(ctx PasswordHashContext, options PasswordHashOptions, appendTo []byte) (res []byte, err error)
	CheckPassword(ctx PasswordHashContext, options PasswordHashOptions, hash []byte) (err error)
}

type PasswordHash interface {
	GetAlgo() string // returns name of hashing algorithm used
	Raw() []byte     // returns encoded form of hash, so if it was parsed again, it would yield same result
}

type PasswordHashParser interface {
	ParsePasswordHash(ctx PasswordHashContext, hash []byte) (res PasswordHash, err error)
}
