// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519_test

import (
	"testing"

	"filippo.io/edwards25519"
)

func BenchmarkAdd(b *testing.B) {
	var x, y edwards25519.FieldElement
	x.One()
	y.Add(edwards25519.One, edwards25519.One)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Add(&x, &y)
	}
}

func BenchmarkMul(b *testing.B) {
	var x, y edwards25519.FieldElement
	x.One()
	y.Add(edwards25519.One, edwards25519.One)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Mul(&x, &y)
	}
}

func BenchmarkMul32(b *testing.B) {
	var x edwards25519.FieldElement
	x.One()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Mul32(&x, 0xaa42aa42)
	}
}
