module asm

go 1.18

require (
	filippo.io/edwards25519 v0.0.0
	github.com/mmcloughlin/avo v0.4.0
)

require (
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/sys v0.0.0-20211030160813-b3129d9d1021 // indirect
	golang.org/x/tools v0.1.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace filippo.io/edwards25519 v0.0.0 => ../..
