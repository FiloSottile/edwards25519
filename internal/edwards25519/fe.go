// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"crypto/subtle"
	"math/big"

	x "github.com/gtank/ristretto255/internal/edwards25519/internal/edwards25519"
)

// FeEqual returns 1 if a and b are equal, and 0 otherwise.
func FeEqual(a, b *FieldElement) int {
	var sa, sb [32]byte
	x.FeToBytes(&sa, a)
	x.FeToBytes(&sb, b)
	return subtle.ConstantTimeCompare(sa[:], sb[:])
}

// FeSelect sets out to v if cond == 1, and to u if cond == 0.
// out, v and u are allowed to overlap.
func FeSelect(out, v, u *FieldElement, cond int) {
	x.FeCMove(out, u, int32(cond^1))
	x.FeCMove(out, v, int32(cond))
}

// FeCondNeg sets u to -u if cond == 1, and to u if cond == 0.
func FeCondNeg(u *FieldElement, cond int) {
	var neg FieldElement
	FeNeg(&neg, u)
	x.FeCMove(u, &neg, int32(cond))
}

// FeAbs sets out to |u|. out and u are allowed to overlap.
func FeAbs(out, u *FieldElement) {
	var neg FieldElement
	FeNeg(&neg, u)
	FeSelect(out, &neg, u, int(FeIsNegative(u)))
}

func feFromBig(dst *FieldElement, n *big.Int) {
	var buf [32]byte
	nn := n.Bytes()
	copy(buf[len(buf)-len(nn):], nn)
	for i := range buf[:len(buf)/2] {
		buf[i], buf[len(buf)-1] = buf[len(buf)-1], buf[i]
	}
	x.FeFromBytes(dst, &buf)
}
