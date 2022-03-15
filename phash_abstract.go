package crypka

type PasswordHashOptions struct {
	Password []byte
	Salt     []byte
}

// PasswordHasher are special kind of hashes.
// Rather than stream data, they accept constant-sized data and yield hash of it.
type PasswordHasher interface {
	HashPassword(ctx PasswordHashContext, options PasswordHashOptions, appendTo []byte) (res []byte, err error)
	CheckPassword(ctx PasswordHashContext, optons PasswordHashOptions, hash []byte) (err error)
}
