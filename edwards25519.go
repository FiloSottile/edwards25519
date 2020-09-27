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
	X, Y, Z, T FieldElement

	// bradfitz's device: make the type not comparable.
	_ [0]func()
}

type projCached struct {
	YplusX, YminusX, Z, T2d FieldElement
}

type affineCached struct {
	YplusX, YminusX, T2d FieldElement
}

// B is the Ed25519 basepoint.
var B = &Point{
	X: FieldElement{1738742601995546, 1146398526822698, 2070867633025821, 562264141797630, 587772402128613},
	Y: FieldElement{1801439850948184, 1351079888211148, 450359962737049, 900719925474099, 1801439850948198},
	Z: FieldElement{1, 0, 0, 0, 0},
	T: FieldElement{1841354044333475, 16398895984059, 755974180946558, 900171276175154, 1821297809914039},
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

// NewPoint returns a new zero Point.
func NewPoint() *Point {
	return (&Point{}).Zero()
}

// Zero sets v to the zero point, and returns v.
func (v *Point) Zero() *Point {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	v.T.Zero()
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
	v.X.Mul(&p.X, &p.T)
	v.Y.Mul(&p.Y, &p.Z)
	v.Z.Mul(&p.Z, &p.T)
	return v
}

func (v *projP2) FromP3(p *Point) *projP2 {
	v.X.Set(&p.X)
	v.Y.Set(&p.Y)
	v.Z.Set(&p.Z)
	return v
}

func (v *Point) fromP1xP1(p *projP1xP1) *Point {
	v.X.Mul(&p.X, &p.T)
	v.Y.Mul(&p.Y, &p.Z)
	v.Z.Mul(&p.Z, &p.T)
	v.T.Mul(&p.X, &p.Y)
	return v
}

func (v *Point) fromP2(p *projP2) *Point {
	v.X.Mul(&p.X, &p.Z)
	v.Y.Mul(&p.Y, &p.Z)
	v.Z.Square(&p.Z)
	v.T.Mul(&p.X, &p.Y)
	return v
}

var d2 = new(FieldElement).Add(D, D)

func (v *projCached) FromP3(p *Point) *projCached {
	v.YplusX.Add(&p.Y, &p.X)
	v.YminusX.Sub(&p.Y, &p.X)
	v.Z.Set(&p.Z)
	v.T2d.Mul(&p.T, d2)
	return v
}

func (v *affineCached) FromP3(p *Point) *affineCached {
	v.YplusX.Add(&p.Y, &p.X)
	v.YminusX.Sub(&p.Y, &p.X)
	v.T2d.Mul(&p.T, d2)

	var invZ FieldElement
	invZ.Invert(&p.Z)
	v.YplusX.Mul(&v.YplusX, &invZ)
	v.YminusX.Mul(&v.YminusX, &invZ)
	v.T2d.Mul(&v.T2d, &invZ)
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

	YplusX.Add(&p.Y, &p.X)
	YminusX.Sub(&p.Y, &p.X)

	PP.Mul(&YplusX, &q.YplusX)
	MM.Mul(&YminusX, &q.YminusX)
	TT2d.Mul(&p.T, &q.T2d)
	ZZ2.Mul(&p.Z, &q.Z)

	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Sub(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&ZZ2, &TT2d)
	v.T.Sub(&ZZ2, &TT2d)
	return v
}

func (v *projP1xP1) Sub(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 FieldElement

	YplusX.Add(&p.Y, &p.X)
	YminusX.Sub(&p.Y, &p.X)

	PP.Mul(&YplusX, &q.YminusX) // flipped sign
	MM.Mul(&YminusX, &q.YplusX) // flipped sign
	TT2d.Mul(&p.T, &q.T2d)
	ZZ2.Mul(&p.Z, &q.Z)

	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Sub(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Sub(&ZZ2, &TT2d) // flipped sign
	v.T.Add(&ZZ2, &TT2d) // flipped sign
	return v
}

func (v *projP1xP1) AddAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 FieldElement

	YplusX.Add(&p.Y, &p.X)
	YminusX.Sub(&p.Y, &p.X)

	PP.Mul(&YplusX, &q.YplusX)
	MM.Mul(&YminusX, &q.YminusX)
	TT2d.Mul(&p.T, &q.T2d)

	Z2.Add(&p.Z, &p.Z)

	v.X.Sub(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&Z2, &TT2d)
	v.T.Sub(&Z2, &TT2d)
	return v
}

func (v *projP1xP1) SubAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 FieldElement

	YplusX.Add(&p.Y, &p.X)
	YminusX.Sub(&p.Y, &p.X)

	PP.Mul(&YplusX, &q.YminusX) // flipped sign
	MM.Mul(&YminusX, &q.YplusX) // flipped sign
	TT2d.Mul(&p.T, &q.T2d)

	Z2.Add(&p.Z, &p.Z)

	v.X.Sub(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Sub(&Z2, &TT2d) // flipped sign
	v.T.Add(&Z2, &TT2d) // flipped sign
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
	v.Z.Sub(&YY, &XX)

	v.X.Sub(&XplusYsq, &v.Y)
	v.T.Sub(&ZZ2, &v.Z)
	return v
}

// Negation.

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	v.X.Neg(&p.X)
	v.Y.Set(&p.Y)
	v.Z.Set(&p.Z)
	v.T.Neg(&p.T)
	return v
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) int {
	var t1, t2, t3, t4 FieldElement
	t1.Mul(&v.X, &u.Z)
	t2.Mul(&u.X, &v.Z)
	t3.Mul(&v.Y, &u.Z)
	t4.Mul(&u.Y, &v.Z)

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
	CondSwap(&v.YplusX, &v.YminusX, cond)
	v.T2d.CondNeg(&v.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1 and leaves it unchanged if cond == 0.
func (v *affineCached) CondNeg(cond int) *affineCached {
	CondSwap(&v.YplusX, &v.YminusX, cond)
	v.T2d.CondNeg(&v.T2d, cond)
	return v
}
