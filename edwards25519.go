// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package edwards25519 implements group logic for the twisted Edwards curve
//
//     -x^2 + y^2 = 1 + -(121665/121666)*x^2*y^2
//
// as well as GF(2^255-19) field arithmetic.
//
// This is better known as the Edwards curve equivalent to Curve25519, and is
// the curve used by the Ed25519 signature scheme.
//
// Most users don't need this package, and should instead use crypto/ed25519 for
// signatures, golang.org/x/crypto/curve25519 for Diffie-Hellman, or
// github.com/gtank/ristretto255 for prime order group logic. However, for
// anyone currently using a fork of crypto/ed25519/internal/edwards25519 or
// github.com/agl/edwards25519, this package should be a safer, faster, and more
// powerful alternative.
package edwards25519

// D is a constant in the curve equation.
var D = &FieldElement{929955233495203, 466365720129213,
	1662059464998953, 2033849074728123, 1442794654840575}

// Point types.

// TODO: write documentation
// TODO: rename (T,X,Y,Z) to (W0,W1,W2,W3) for P2 and P3 models?
// https://doc-internal.dalek.rs/curve25519_dalek/backend/serial/curve_models/index.html

type projP1xP1 struct {
	X, Y, Z, T FieldElement
}

type projP2 struct {
	X, Y, Z FieldElement
}

type Point struct {
	x, y, z, t FieldElement

	// Make the type not comparable with bradfitz's device, since equal points
	// can be represented by different Go values.
	_ [0]func()
}

type projCached struct {
	YplusX, YminusX, Z, T2d FieldElement
}

type affineCached struct {
	YplusX, YminusX, T2d FieldElement
}

// Constructors.

func (v *projP1xP1) Zero() *projP1xP1 {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	v.T.One()
	return v
}

func (v *projP2) Zero() *projP2 {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	return v
}

// NewIdentityPoint returns a new Point set to the identity.
func NewIdentityPoint() *Point {
	return (&Point{}).Identity()
}

// Identity sets v to the zero point, and returns v.
func (v *Point) Identity() *Point {
	v.x.Zero()
	v.y.One()
	v.z.One()
	v.t.Zero()
	return v
}

// NewGeneratorPoint returns a new Point set to the canonical generator.
func NewGeneratorPoint() *Point {
	return (&Point{}).Generator()
}

// Generator sets v to the canonical generator, and returns v.
func (v *Point) Generator() *Point {
	v.x = FieldElement{1738742601995546, 1146398526822698,
		2070867633025821, 562264141797630, 587772402128613}
	v.y = FieldElement{1801439850948184, 1351079888211148,
		450359962737049, 900719925474099, 1801439850948198}
	v.z.One()
	v.t = FieldElement{1841354044333475, 16398895984059,
		755974180946558, 900171276175154, 1821297809914039}
	return v
}

func (v *projCached) Zero() *projCached {
	v.YplusX.One()
	v.YminusX.One()
	v.Z.One()
	v.T2d.Zero()
	return v
}

func (v *affineCached) Zero() *affineCached {
	v.YplusX.One()
	v.YminusX.One()
	v.T2d.Zero()
	return v
}

// Assignments.

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	*v = *u
	return v
}

// Conversions.

func (v *projP2) FromP1xP1(p *projP1xP1) *projP2 {
	v.X.Multiply(&p.X, &p.T)
	v.Y.Multiply(&p.Y, &p.Z)
	v.Z.Multiply(&p.Z, &p.T)
	return v
}

func (v *projP2) FromP3(p *Point) *projP2 {
	v.X.Set(&p.x)
	v.Y.Set(&p.y)
	v.Z.Set(&p.z)
	return v
}

func (v *Point) fromP1xP1(p *projP1xP1) *Point {
	v.x.Multiply(&p.X, &p.T)
	v.y.Multiply(&p.Y, &p.Z)
	v.z.Multiply(&p.Z, &p.T)
	v.t.Multiply(&p.X, &p.Y)
	return v
}

func (v *Point) fromP2(p *projP2) *Point {
	v.x.Multiply(&p.X, &p.Z)
	v.y.Multiply(&p.Y, &p.Z)
	v.z.Square(&p.Z)
	v.t.Multiply(&p.X, &p.Y)
	return v
}

// FromExtendedCoords sets v = (x, y, z, t) in extended Edwards coordinates
// (see https://eprint.iacr.org/2008/522), and returns v.
func (v *Point) FromExtendedCoords(x, y, z, t *FieldElement) *Point {
	v.x.Set(x)
	v.y.Set(y)
	v.z.Set(z)
	v.t.Set(t)
	return v
}

// ExtendedCoords returns v in extended Edwards coordinates (see
// https://eprint.iacr.org/2008/522).
func (v *Point) ExtendedCoords() (x, y, z, t *FieldElement) {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var w0, w1, w2, w3 FieldElement
	return v.extendedCoords(&w0, &w1, &w2, &w3)
}

func (v *Point) extendedCoords(x, y, z, t *FieldElement) (
	*FieldElement, *FieldElement, *FieldElement, *FieldElement) {
	x.Set(&v.x)
	y.Set(&v.y)
	z.Set(&v.z)
	t.Set(&v.t)
	return x, y, z, t
}

var d2 = new(FieldElement).Add(D, D)

func (v *projCached) FromP3(p *Point) *projCached {
	v.YplusX.Add(&p.y, &p.x)
	v.YminusX.Subtract(&p.y, &p.x)
	v.Z.Set(&p.z)
	v.T2d.Multiply(&p.t, d2)
	return v
}

func (v *affineCached) FromP3(p *Point) *affineCached {
	v.YplusX.Add(&p.y, &p.x)
	v.YminusX.Subtract(&p.y, &p.x)
	v.T2d.Multiply(&p.t, d2)

	var invZ FieldElement
	invZ.Invert(&p.z)
	v.YplusX.Multiply(&v.YplusX, &invZ)
	v.YminusX.Multiply(&v.YminusX, &invZ)
	v.T2d.Multiply(&v.T2d, &invZ)
	return v
}

// (Re)addition and subtraction.

// Add sets v = p + q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	result := projP1xP1{}
	qCached := projCached{}
	qCached.FromP3(q)
	result.Add(p, &qCached)
	v.fromP1xP1(&result)
	return v
}

// Subtract sets v = p - q, and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	result := projP1xP1{}
	qCached := projCached{}
	qCached.FromP3(q)
	result.Sub(p, &qCached)
	v.fromP1xP1(&result)
	return v
}

func (v *projP1xP1) Add(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 FieldElement

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YplusX)
	MM.Multiply(&YminusX, &q.YminusX)
	TT2d.Multiply(&p.t, &q.T2d)
	ZZ2.Multiply(&p.z, &q.Z)

	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&ZZ2, &TT2d)
	v.T.Subtract(&ZZ2, &TT2d)
	return v
}

func (v *projP1xP1) Sub(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 FieldElement

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YminusX) // flipped sign
	MM.Multiply(&YminusX, &q.YplusX) // flipped sign
	TT2d.Multiply(&p.t, &q.T2d)
	ZZ2.Multiply(&p.z, &q.Z)

	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Subtract(&ZZ2, &TT2d) // flipped sign
	v.T.Add(&ZZ2, &TT2d)      // flipped sign
	return v
}

func (v *projP1xP1) AddAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 FieldElement

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YplusX)
	MM.Multiply(&YminusX, &q.YminusX)
	TT2d.Multiply(&p.t, &q.T2d)

	Z2.Add(&p.z, &p.z)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&Z2, &TT2d)
	v.T.Subtract(&Z2, &TT2d)
	return v
}

func (v *projP1xP1) SubAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 FieldElement

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YminusX) // flipped sign
	MM.Multiply(&YminusX, &q.YplusX) // flipped sign
	TT2d.Multiply(&p.t, &q.T2d)

	Z2.Add(&p.z, &p.z)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Subtract(&Z2, &TT2d) // flipped sign
	v.T.Add(&Z2, &TT2d)      // flipped sign
	return v
}

// Doubling.

func (v *projP1xP1) Double(p *projP2) *projP1xP1 {
	var XX, YY, ZZ2, XplusYsq FieldElement

	XX.Square(&p.X)
	YY.Square(&p.Y)
	ZZ2.Square(&p.Z)
	ZZ2.Add(&ZZ2, &ZZ2)
	XplusYsq.Add(&p.X, &p.Y)
	XplusYsq.Square(&XplusYsq)

	v.Y.Add(&YY, &XX)
	v.Z.Subtract(&YY, &XX)

	v.X.Subtract(&XplusYsq, &v.Y)
	v.T.Subtract(&ZZ2, &v.Z)
	return v
}

// Negation.

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	v.x.Negate(&p.x)
	v.y.Set(&p.y)
	v.z.Set(&p.z)
	v.t.Negate(&p.t)
	return v
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) int {
	var t1, t2, t3, t4 FieldElement
	t1.Multiply(&v.x, &u.z)
	t2.Multiply(&u.x, &v.z)
	t3.Multiply(&v.y, &u.z)
	t4.Multiply(&u.y, &v.z)

	return t1.Equal(&t2) & t3.Equal(&t4)
}

// Constant-time operations

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *projCached) Select(a, b *projCached, cond int) *projCached {
	v.YplusX.Select(&a.YplusX, &b.YplusX, cond)
	v.YminusX.Select(&a.YminusX, &b.YminusX, cond)
	v.Z.Select(&a.Z, &b.Z, cond)
	v.T2d.Select(&a.T2d, &b.T2d, cond)
	return v
}

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *affineCached) Select(a, b *affineCached, cond int) *affineCached {
	v.YplusX.Select(&a.YplusX, &b.YplusX, cond)
	v.YminusX.Select(&a.YminusX, &b.YminusX, cond)
	v.T2d.Select(&a.T2d, &b.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1 and leaves it unchanged if cond == 0.
func (v *projCached) CondNeg(cond int) *projCached {
	v.YplusX.Swap(&v.YminusX, cond)
	v.T2d.condNeg(&v.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1 and leaves it unchanged if cond == 0.
func (v *affineCached) CondNeg(cond int) *affineCached {
	v.YplusX.Swap(&v.YminusX, cond)
	v.T2d.condNeg(&v.T2d, cond)
	return v
}
