// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
	"testing/quick"
)

var (
	// quickCheckConfig32 will make each quickcheck test run (32 * -quickchecks)
	// times. The default value of -quickchecks is 100.
	quickCheckConfig32 = &quick.Config{MaxCountScale: 1 << 5}

	// a random scalar generated using dalek.
	dalekScalar = Scalar{[32]byte{219, 106, 114, 9, 174, 249, 155, 89, 69, 203, 201, 93, 92, 116, 234, 187, 78, 115, 103, 172, 182, 98, 62, 103, 187, 136, 13, 100, 248, 110, 12, 4}}
	// the above, times the edwards25519 basepoint.
	dalekScalarBasepoint = Point{
		x: fieldElement{778774234987948, 1589187156384239, 1213330452914652, 186161118421127, 2186284806803213},
		y: fieldElement{1241255309069369, 1115278942994853, 1016511918109334, 1303231926552315, 1801448517689873},
		z: fieldElement{353337085654440, 1327844406437681, 2207296012811921, 707394926933424, 917408459573183},
		t: fieldElement{585487439439725, 1792815221887900, 946062846079052, 1954901232609667, 1418300670001780},
	}
)

func TestScalarMultSmallScalars(t *testing.T) {
	var z Scalar
	var p Point
	p.ScalarMult(&z, B)
	if I.Equal(&p) != 1 {
		t.Error("0*B != 0")
	}
	checkOnCurve(t, &p)

	z = Scalar{[32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	p.ScalarMult(&z, B)
	if B.Equal(&p) != 1 {
		t.Error("1*B != 1")
	}
	checkOnCurve(t, &p)
}

func TestScalarMultVsDalek(t *testing.T) {
	var p Point
	p.ScalarMult(&dalekScalar, B)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("Scalar mul does not match dalek")
	}
	checkOnCurve(t, &p)
}

func TestBasepointMulVsDalek(t *testing.T) {
	var p Point
	p.ScalarBaseMult(&dalekScalar)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("Scalar mul does not match dalek")
	}
	checkOnCurve(t, &p)
}

func TestVartimeDoubleBaseMulVsDalek(t *testing.T) {
	var p Point
	var z Scalar
	p.VarTimeDoubleScalarBaseMult(&dalekScalar, B, &z)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("VartimeDoubleBaseMul fails with b=0")
	}
	checkOnCurve(t, &p)
	p.VarTimeDoubleScalarBaseMult(&z, B, &dalekScalar)
	if dalekScalarBasepoint.Equal(&p) != 1 {
		t.Error("VartimeDoubleBaseMul fails with a=0")
	}
	checkOnCurve(t, &p)
}

func TestScalarMulDistributesOverAdd(t *testing.T) {
	scalarMulDistributesOverAdd := func(x, y Scalar) bool {
		var z Scalar
		z.Add(&x, &y)
		var p, q, r, check Point
		p.ScalarMult(&x, B)
		q.ScalarMult(&y, B)
		r.ScalarMult(&z, B)
		check.Add(&p, &q)
		checkOnCurve(t, &p, &q, &r, &check)
		return check.Equal(&r) == 1
	}

	if err := quick.Check(scalarMulDistributesOverAdd, quickCheckConfig32); err != nil {
		t.Error(err)
	}
}

func TestBasepointTableGeneration(t *testing.T) {
	// The basepoint table is 32 affineLookupTables,
	// corresponding to (16^2i)*B for table i.

	tmp1 := &projP1xP1{}
	tmp2 := &projP2{}
	tmp3 := &Point{}
	tmp3.Set(B)
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
		tmp3.fromP1xP1(tmp1)
		checkOnCurve(t, tmp3)
	}
}

func TestScalarMulMatchesBasepointMul(t *testing.T) {
	scalarMulMatchesBasepointMul := func(x Scalar) bool {
		var p, q Point
		p.ScalarMult(&x, B)
		q.ScalarBaseMult(&x)
		checkOnCurve(t, &p, &q)
		return p.Equal(&q) == 1
	}

	if err := quick.Check(scalarMulMatchesBasepointMul, quickCheckConfig32); err != nil {
		t.Error(err)
	}
}

func TestMultiScalarMulMatchesBasepointMul(t *testing.T) {
	multiScalarMulMatchesBasepointMul := func(x, y, z Scalar) bool {
		var p, q1, q2, q3, check Point

		p.MultiScalarMult([]*Scalar{&x, &y, &z}, []*Point{B, B, B})

		q1.ScalarBaseMult(&x)
		q2.ScalarBaseMult(&y)
		q3.ScalarBaseMult(&z)
		check.Add(&q1, &q2).Add(&check, &q3)

		checkOnCurve(t, &p, &check, &q1, &q2, &q3)
		return p.Equal(&check) == 1
	}

	if err := quick.Check(multiScalarMulMatchesBasepointMul, quickCheckConfig32); err != nil {
		t.Error(err)
	}
}

func TestBasepointNafTableGeneration(t *testing.T) {
	var table nafLookupTable8
	table.FromP3(B)

	if table != basepointNafTable {
		t.Error("BasepointNafTable does not match")
	}
}

func TestVartimeDoubleBaseMulMatchesBasepointMul(t *testing.T) {
	vartimeDoubleBaseMulMatchesBasepointMul := func(x, y Scalar) bool {
		var p, q1, q2, check Point

		p.VarTimeDoubleScalarBaseMult(&x, B, &y)

		q1.ScalarBaseMult(&x)
		q2.ScalarBaseMult(&y)
		check.Add(&q1, &q2)

		checkOnCurve(t, &p, &check, &q1, &q2)
		return p.Equal(&check) == 1
	}

	if err := quick.Check(vartimeDoubleBaseMulMatchesBasepointMul, quickCheckConfig32); err != nil {
		t.Error(err)
	}
}

func TestVartimeMultiScalarMulMatchesBasepointMul(t *testing.T) {
	vartimeMultiScalarMulMatchesBasepointMul := func(x, y, z Scalar) bool {
		var p, q1, q2, q3, check Point

		p.VarTimeMultiScalarMult([]*Scalar{&x, &y, &z}, []*Point{B, B, B})

		q1.ScalarBaseMult(&x)
		q2.ScalarBaseMult(&y)
		q3.ScalarBaseMult(&z)
		check.Add(&q1, &q2).Add(&check, &q3)

		checkOnCurve(t, &p, &check, &q1, &q2, &q3)
		return p.Equal(&check) == 1
	}

	if err := quick.Check(vartimeMultiScalarMulMatchesBasepointMul, quickCheckConfig32); err != nil {
		t.Error(err)
	}
}

// Benchmarks.

func BenchmarkBasepointMul(t *testing.B) {
	var p Point

	for i := 0; i < t.N; i++ {
		p.ScalarBaseMult(&dalekScalar)
	}
}

func BenchmarkScalarMul(t *testing.B) {
	var p Point

	for i := 0; i < t.N; i++ {
		p.ScalarMult(&dalekScalar, B)
	}
}

func BenchmarkVartimeDoubleBaseMul(t *testing.B) {
	var p Point

	for i := 0; i < t.N; i++ {
		p.VarTimeDoubleScalarBaseMult(&dalekScalar, B, &dalekScalar)
	}
}

func BenchmarkMultiscalarMulSize8(t *testing.B) {
	var p Point
	x := dalekScalar

	for i := 0; i < t.N; i++ {
		p.MultiScalarMult([]*Scalar{&x, &x, &x, &x, &x, &x, &x, &x}, []*Point{B, B, B, B, B, B, B, B})
	}
}

// TODO: add BenchmarkVartimeMultiscalarMulSize8 (need to have
// different scalars & points to measure cache effects).
