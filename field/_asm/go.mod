module crypto/internal/fips140/edwards25519/field/_asm

go 1.25

require github.com/mmcloughlin/avo v0.6.0

require (
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/tools v0.16.1 // indirect
)

require filippo.io/edwards25519 v0.0.0

replace filippo.io/edwards25519 v0.0.0 => ../..
