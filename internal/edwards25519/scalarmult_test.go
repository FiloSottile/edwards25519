// Copyright 2019 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
	"testing/quick"

	"github.com/gtank/ristretto255/internal/radix51"
	"github.com/gtank/ristretto255/internal/scalar"
)

// quickCheckConfig will make each quickcheck test run (2^6 * -quickchecks)
// times. The default value of -quickchecks is 100.
var (
	quickCheckConfig = &quick.Config{MaxCountScale: 1 << 6}

	// a random scalar generated using dalek.
	dalekScalar = scalar.Scalar([32]byte{219, 106, 114, 9, 174, 249, 155, 89, 69, 203, 201, 93, 92, 116, 234, 187, 78, 115, 103, 172, 182, 98, 62, 103, 187, 136, 13, 100, 248, 110, 12, 4})
	// the above, times the Ed25519 basepoint.
	dalekScalarBasepoint = ProjP3{
		X: radix51.FieldElement([5]uint64{778774234987948, 1589187156384239, 1213330452914652, 186161118421127, 2186284806803213}),
		Y: radix51.FieldElement([5]uint64{1241255309069369, 1115278942994853, 1016511918109334, 1303231926552315, 1801448517689873}),
		Z: radix51.FieldElement([5]uint64{353337085654440, 1327844406437681, 2207296012811921, 707394926933424, 917408459573183}),
		T: radix51.FieldElement([5]uint64{585487439439725, 1792815221887900, 946062846079052, 1954901232609667, 1418300670001780}),
	}
)

func TestScalarMulSmallScalars(t *testing.T) {
	var z scalar.Scalar
	var p, check ProjP3
	p.ScalarMul(&z, &B)
	check.Zero()
	if check.Equal(&p) != 1 {
		t.Error("0*B != 0")
	}

	z = scalar.Scalar([32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	p.ScalarMul(&z, &B)
	check.Set(&B)
	if check.Equal(&p) != 1 {
		t.Error("1*B != 1")
	}
}

func TestScalarMulVsDalek(t *testing.T) {
	var p ProjP3
	p.ScalarMul(&dalekScalar, &B)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("Scalar mul does not match dalek")
	}
}

func TestBasepointMulVsDalek(t *testing.T) {
	var p ProjP3
	p.BasepointMul(&dalekScalar)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("Scalar mul does not match dalek")
	}
}

func TestVartimeDoubleBaseMulVsDalek(t *testing.T) {
	var p ProjP3
	var z scalar.Scalar
	p.VartimeDoubleBaseMul(&dalekScalar, &B, &z)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("VartimeDoubleBaseMul fails with b=0")
	}
	p.VartimeDoubleBaseMul(&z, &B, &dalekScalar)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("VartimeDoubleBaseMul fails with a=0")
	}
}

func TestScalarMulDistributesOverAdd(t *testing.T) {
	scalarMulDistributesOverAdd := func(x, y scalar.Scalar) bool {
		// The quickcheck generation strategy chooses a random
		// 32-byte array, but we require that the high bit is
		// unset.  FIXME: make Scalar opaque.  Until then,
		// mask the high bits:
		x[31] &= 127
		y[31] &= 127
		var z scalar.Scalar
		z.Add(&x, &y)
		var p, q, r, check ProjP3
		p.ScalarMul(&x, &B)
		q.ScalarMul(&y, &B)
		r.ScalarMul(&z, &B)
		check.Add(&p, &q)
		return check.Equal(&r) == 1
	}

	if err := quick.Check(scalarMulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestBasepointTableGeneration(t *testing.T) {
	// The basepoint table is 32 affineLookupTables,
	// corresponding to (16^2i)*B for table i.

	tmp1 := &ProjP1xP1{}
	tmp2 := &ProjP2{}
	tmp3 := &ProjP3{}
	tmp3.Set(&B)
	table := make([]affineLookupTable, 32)
	for i := 0; i < 32; i++ {
		// Build the table
		table[i].FromP3(tmp3)
		// Assert equality with the hardcoded one
		if table[i] != basepointTable[i] {
			t.Errorf("Basepoint table %d does not match", i)
		}

		// Set p = (16^2)*p = 256*p = 2^8*p
		tmp2.FromP3(tmp3)
		for j := 0; j < 7; j++ {
			tmp1.Double(tmp2)
			tmp2.FromP1xP1(tmp1)
		}
		tmp1.Double(tmp2)
		tmp3.FromP1xP1(tmp1)
	}
}

func TestScalarMulMatchesBasepointMul(t *testing.T) {
	scalarMulMatchesBasepointMul := func(x scalar.Scalar) bool {
		// FIXME opaque scalars
		x[31] &= 127
		var p, q ProjP3
		p.ScalarMul(&x, &B)
		q.BasepointMul(&x)
		return p.Equal(&q) == 1
	}

	if err := quick.Check(scalarMulMatchesBasepointMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestMultiScalarMulMatchesBasepointMul(t *testing.T) {
	multiScalarMulMatchesBasepointMul := func(x, y, z scalar.Scalar) bool {
		// FIXME opaque scalars
		x[31] &= 127
		y[31] &= 127
		z[31] &= 127
		var p, q1, q2, q3, check ProjP3

		p.MultiscalarMul([]scalar.Scalar{x, y, z}, []*ProjP3{&B, &B, &B})

		q1.BasepointMul(&x)
		q2.BasepointMul(&y)
		q3.BasepointMul(&z)
		check.Zero()
		check.Add(&q1, &q2).Add(&check, &q3)

		return p.Equal(&check) == 1
	}

	if err := quick.Check(multiScalarMulMatchesBasepointMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestBasepointNafTableGeneration(t *testing.T) {
	var table nafLookupTable8
	table.FromP3(&B)

	if table != basepointNafTable {
		t.Error("BasepointNafTable does not match")
	}
}

func TestVartimeDoubleBaseMulMatchesBasepointMul(t *testing.T) {
	vartimeDoubleBaseMulMatchesBasepointMul := func(x, y scalar.Scalar) bool {
		// FIXME opaque scalars
		x[31] &= 127
		y[31] &= 127
		var p, q1, q2, check ProjP3

		p.VartimeDoubleBaseMul(&x, &B, &y)

		q1.BasepointMul(&x)
		q2.BasepointMul(&y)
		check.Zero()
		check.Add(&q1, &q2)

		return p.Equal(&check) == 1
	}

	if err := quick.Check(vartimeDoubleBaseMulMatchesBasepointMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestVartimeMultiScalarMulMatchesBasepointMul(t *testing.T) {
	vartimeMultiScalarMulMatchesBasepointMul := func(x, y, z scalar.Scalar) bool {
		// FIXME opaque scalars
		x[31] &= 127
		y[31] &= 127
		z[31] &= 127
		var p, q1, q2, q3, check ProjP3

		p.VartimeMultiscalarMul([]scalar.Scalar{x, y, z}, []*ProjP3{&B, &B, &B})

		q1.BasepointMul(&x)
		q2.BasepointMul(&y)
		q3.BasepointMul(&z)
		check.Zero()
		check.Add(&q1, &q2).Add(&check, &q3)

		return p.Equal(&check) == 1
	}

	if err := quick.Check(vartimeMultiScalarMulMatchesBasepointMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

// Benchmarks.

func BenchmarkBasepointMul(t *testing.B) {
	var p ProjP3

	for i := 0; i < t.N; i++ {
		p.BasepointMul(&dalekScalar)
	}
}

func BenchmarkScalarMul(t *testing.B) {
	var p ProjP3

	for i := 0; i < t.N; i++ {
		p.ScalarMul(&dalekScalar, &B)
	}
}

func BenchmarkVartimeDoubleBaseMul(t *testing.B) {
	var p ProjP3

	for i := 0; i < t.N; i++ {
		p.VartimeDoubleBaseMul(&dalekScalar, &B, &dalekScalar)
	}
}

func BenchmarkMultiscalarMulSize8(t *testing.B) {
	var p ProjP3
	x := dalekScalar

	for i := 0; i < t.N; i++ {
		p.MultiscalarMul([]scalar.Scalar{x, x, x, x, x, x, x, x}, []*ProjP3{&B, &B, &B, &B, &B, &B, &B, &B})
	}
}

// TODO: add BenchmarkVartimeMultiscalarMulSize8 (need to have
// different scalars & points to measure cache effects).
