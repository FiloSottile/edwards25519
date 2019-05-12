// Copyright 2019 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scalar

import (
	"bytes"
	"testing"
	"testing/quick"
)

// quickCheckConfig will make each quickcheck test run (1024 * -quickchecks)
// times. The default value of -quickchecks is 100.
var quickCheckConfig = &quick.Config{MaxCountScale: 1 << 10}

func TestFromBytesRoundTrip(t *testing.T) {
	f1 := func(in, out [32]byte, sc Scalar) bool {
		in[len(in)-1] &= (1 << 4) - 1 // Mask out top 4 bits for 252-bit numbers
		sc.FromBytes(in[:])
		sc.Bytes(out[:0])
		return bytes.Equal(in[:], out[:]) && sc.IsCanonical()
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Errorf("failed bytes->scalar->bytes round-trip: %v", err)
	}

	f2 := func(sc1, sc2 Scalar, out [32]byte) bool {
		sc1.Bytes(out[:0])
		sc2.FromBytes(out[:])

		sc1.reduce()
		sc2.reduce()
		return sc1 == sc2
	}
	if err := quick.Check(f2, nil); err != nil {
		t.Errorf("failed scalar->bytes->scalar round-trip: %v", err)
	}
}

func TestMulDistributesOverAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z Scalar) bool {
		// Compute t1 = (x+y)*z
		var t1 Scalar
		t1.Add(&x, &y)
		t1.Mul(&t1, &z)

		// Compute t2 = x*z + y*z
		var t2 Scalar
		var t3 Scalar
		t2.Mul(&x, &z)
		t3.Mul(&y, &z)
		t2.Add(&t2, &t3)

		return t1.Equal(&t2) == 1 && t1.IsCanonical() && t2.IsCanonical()
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestNonAdjacentForm(t *testing.T) {
	s := Scalar([32]byte{
		0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d,
		0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8, 0x26, 0x4d,
		0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1,
		0x58, 0x9e, 0x7b, 0x7f, 0x23, 0x76, 0xef, 0x09,
	})
	expectedNaf := [256]int8{
		0, 13, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, -11, 0, 0, 0, 0, 3, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 9, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 11, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0,
		-9, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 9, 0,
		0, 0, 0, -15, 0, 0, 0, 0, -7, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, -3, 0,
		0, 0, 0, -11, 0, 0, 0, 0, -7, 0, 0, 0, 0, -13, 0, 0, 0, 0, 11, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, -15, 0, 0, 0, 0, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0,
		0, 0, 0, 11, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 7,
		0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	}

	sNaf := s.NonAdjacentForm(5)

	for i := 0; i < 256; i++ {
		if expectedNaf[i] != sNaf[i] {
			t.Errorf("Wrong digit at position %d, got %d, expected %d", i, sNaf[i], expectedNaf[i])
		}
	}
}

func TestInvert(t *testing.T) {
	invertWorks := func(x Scalar) bool {
		var xInv, check Scalar
		xInv.Inv(&x)
		check.Mul(&x, &xInv)

		return check.Equal(&scOne) == 1
	}

	if err := quick.Check(invertWorks, quickCheckConfig); err != nil {
		t.Error(err)
	}
}
