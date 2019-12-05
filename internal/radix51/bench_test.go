// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix51_test

import (
	"testing"

	"github.com/gtank/ristretto255/internal/radix51"
)

func BenchmarkAdd(b *testing.B) {
	var x, y radix51.FieldElement
	x.One()
	y.Add(radix51.One, radix51.One)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Add(&x, &y)
	}
}

func BenchmarkMul(b *testing.B) {
	var x, y radix51.FieldElement
	x.One()
	y.Add(radix51.One, radix51.One)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Mul(&x, &y)
	}
}

func BenchmarkMul32(b *testing.B) {
	var x radix51.FieldElement
	x.One()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Mul32(&x, 0xaa42aa42)
	}
}
