// Copyright 2016 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"crypto/subtle"
	"math/big"

	// This is exactly as horrible as it should be.
	. "github.com/gtank/ristretto255/internal/edwards25519/internal/edwards25519"
)

// FeEqual returns 1 if a and b are equal, and 0 otherwise.
func FeEqual(a, b *FieldElement) int {
	var sa, sb [32]byte
	FeToBytes(&sa, a)
	FeToBytes(&sb, b)
	return subtle.ConstantTimeCompare(sa[:], sb[:])
}

func feFromBig(dst *FieldElement, n *big.Int) {
	var buf [32]byte
	nn := n.Bytes()
	copy(buf[len(buf)-len(nn):], nn)
	for i := range buf[:len(buf)/2] {
		buf[i], buf[len(buf)-1] = buf[len(buf)-1], buf[i]
	}
	FeFromBytes(dst, &buf)
}
