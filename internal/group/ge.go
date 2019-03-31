// Copyright (c) 2017 George Tankersley. All rights reserved.
// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package group implements group logic for the Ed25519 curve.
package group

import (
	"math/big"

	"github.com/gtank/ed25519/internal/radix51"
)

// D is a constant in the curve equation.
var D = &radix51.FieldElement{929955233495203, 466365720129213,
	1662059464998953, 2033849074728123, 1442794654840575}

// From EFD https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
// An elliptic curve in twisted Edwards form has parameters a, d and coordinates
// x, y satisfying the following equations:
//
//     a * x^2 + y^2 = 1 + d * x^2 * y^2
//
// Extended coordinates assume a = -1 and represent x, y as (X, Y, Z, T)
// satisfying the following equations:
//
//     x = X / Z
//     y = Y / Z
//     x * y = T / Z
//
// This representation was introduced in the HisilWongCarterDawson paper "Twisted
// Edwards curves revisited" (Asiacrypt 2008).
type ExtendedGroupElement struct {
	X, Y, Z, T radix51.FieldElement
}

// Converts (x,y) to (X:Y:T:Z) extended coordinates, or "P3" in ref10. As
// described in "Twisted Edwards Curves Revisited", Hisil-Wong-Carter-Dawson
// 2008, Section 3.1 (https://eprint.iacr.org/2008/522.pdf)
// See also https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
func (v *ExtendedGroupElement) FromAffine(x, y *big.Int) *ExtendedGroupElement {
	v.X.FromBig(x)
	v.Y.FromBig(y)
	v.T.Mul(&v.X, &v.Y)
	v.Z.One()
	return v
}

// Extended coordinates are XYZT with x = X/Z, y = Y/Z, or the "P3"
// representation in ref10. Extended->affine is the same operation as moving
// from projective to affine. Per HWCD, it is safe to move from extended to
// projective by simply ignoring T.
func (v *ExtendedGroupElement) ToAffine() (*big.Int, *big.Int) {
	var x, y, zinv radix51.FieldElement

	zinv.Invert(&v.Z)
	x.Mul(&v.X, &zinv)
	y.Mul(&v.Y, &zinv)

	return x.ToBig(), y.ToBig()
}

// Per HWCD, it is safe to move from extended to projective by simply ignoring T.
func (v *ExtendedGroupElement) ToProjective(p *ProjectiveGroupElement) {
	p.X.Set(&v.X)
	p.Y.Set(&v.Y)
	p.Z.Set(&v.Z)
}

func (v *ExtendedGroupElement) Zero() *ExtendedGroupElement {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	v.T.Zero()
	return v
}

var twoD = new(radix51.FieldElement).Add(D, D)

// This is the same addition formula everyone uses, "add-2008-hwcd-3".
// https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
// TODO We know Z1=1 and Z2=1 here, so mmadd-2008-hwcd-3 (6M + 1S + 1*k + 9add) could apply
func (v *ExtendedGroupElement) Add(p1, p2 *ExtendedGroupElement) *ExtendedGroupElement {
	var tmp1, tmp2, A, B, C, D, E, F, G, H radix51.FieldElement
	tmp1.Sub(&p1.Y, &p1.X) // tmp1 <-- Y1-X1
	tmp2.Sub(&p2.Y, &p2.X) // tmp2 <-- Y2-X2
	A.Mul(&tmp1, &tmp2)    // A <-- tmp1*tmp2 = (Y1-X1)*(Y2-X2)
	tmp1.Add(&p1.Y, &p1.X) // tmp1 <-- Y1+X1
	tmp2.Add(&p2.Y, &p2.X) // tmp2 <-- Y2+X2
	B.Mul(&tmp1, &tmp2)    // B <-- tmp1*tmp2 = (Y1+X1)*(Y2+X2)
	tmp1.Mul(&p1.T, &p2.T) // tmp1 <-- T1*T2
	C.Mul(&tmp1, twoD)     // C <-- tmp1*2d = T1*2*d*T2
	tmp1.Mul(&p1.Z, &p2.Z) // tmp1 <-- Z1*Z2
	D.Add(&tmp1, &tmp1)    // D <-- tmp1 + tmp1 = 2*Z1*Z2
	E.Sub(&B, &A)          // E <-- B-A
	F.Sub(&D, &C)          // F <-- D-C
	G.Add(&D, &C)          // G <-- D+C
	H.Add(&B, &A)          // H <-- B+A
	v.X.Mul(&E, &F)        // X3 <-- E*F
	v.Y.Mul(&G, &H)        // Y3 <-- G*H
	v.T.Mul(&E, &H)        // T3 <-- E*H
	v.Z.Mul(&F, &G)        // Z3 <-- F*G
	return v
}

// This implements the explicit formulas from HWCD Section 3.3, "Dedicated
// Doubling in [extended coordinates]".
//
// Explicit formula is as follows. Cost is 4M + 4S + 1D. For Ed25519, a = -1:
//
//       A ← X1^2
//       B ← Y1^2
//       C ← 2*Z1^2
//       D ← a*A
//       E ← (X1+Y1)^2 − A − B
//       G ← D+B
//       F ← G−C
//       H ← D−B
//       X3 ← E*F
//       Y3 ← G*H
//       T3 ← E*H
//       Z3 ← F*G
//
// In ref10/donna/dalek etc, this is instead handled by a faster
// mixed-coordinate doubling that results in a "Completed" group element
// instead of another point in extended coordinates. I have implemented it
// this way to see if more straightforward code is worth the (hopefully small)
// performance tradeoff.
func (v *ExtendedGroupElement) Double(u *ExtendedGroupElement) *ExtendedGroupElement {
	// TODO: Convert to projective coordinates? Section 4.3 mixed doubling?

	var A, B, C, D, E, F, G, H radix51.FieldElement

	// A ← X1^2, B ← Y1^2
	A.Square(&u.X)
	B.Square(&u.Y)

	// C ← 2*Z1^2
	C.Square(&u.Z)
	C.Add(&C, &C) // TODO should probably implement FeSquare2

	// D ← -1*A
	D.Neg(&A) // implemented as subtraction

	// E ← (X1+Y1)^2 − A − B
	var t0 radix51.FieldElement
	t0.Add(&u.X, &u.Y)
	t0.Square(&t0)
	E.Sub(&t0, &A)
	E.Sub(&E, &B)

	G.Add(&D, &B)   // G ← D+B
	F.Sub(&G, &C)   // F ← G−C
	H.Sub(&D, &B)   // H ← D−B
	v.X.Mul(&E, &F) // X3 ← E*F
	v.Y.Mul(&G, &H) // Y3 ← G*H
	v.T.Mul(&E, &H) // T3 ← E*H
	v.Z.Mul(&F, &G) // Z3 ← F*G

	return v
}

// Projective coordinates are XYZ with x = X/Z, y = Y/Z, or the "P2"
// representation in ref10. This representation has a cheaper doubling formula
// than extended coordinates.
type ProjectiveGroupElement struct {
	X, Y, Z radix51.FieldElement
}

func (v *ProjectiveGroupElement) FromAffine(x, y *big.Int) *ProjectiveGroupElement {
	v.X.FromBig(x)
	v.Y.FromBig(y)
	v.Z.One()
	return v
}

func (v *ProjectiveGroupElement) ToAffine() (*big.Int, *big.Int) {
	var x, y, zinv radix51.FieldElement

	zinv.Invert(&v.Z)
	x.Mul(&v.X, &zinv)
	y.Mul(&v.Y, &zinv)

	return x.ToBig(), y.ToBig()
}

// HWCD Section 3: "Given (X : Y : Z) in [projective coordinates] passing to
// [extended coordinates, (X : Y : T : Z)] can be performed in 3M+1S by computing
// (XZ, YZ, XY, Z^2)"
func (v *ProjectiveGroupElement) ToExtended(r *ExtendedGroupElement) {
	r.X.Mul(&v.X, &v.Z)
	r.Y.Mul(&v.Y, &v.Z)
	r.T.Mul(&v.X, &v.Y)
	r.Z.Square(&v.Z)
}

func (v *ProjectiveGroupElement) Zero() *ProjectiveGroupElement {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	return v
}

// Because we are often converting from affine, we can use "mdbl-2008-bbjlp"
// which assumes Z1=1. We also assume a = -1.
//
// Assumptions: Z1 = 1.
// Cost: 2M + 4S + 1*a + 7add + 1*2.
// Source: 2008 BernsteinBirknerJoyeLangePeters
//         http://eprint.iacr.org/2008/013, plus Z1=1, plus standard simplification.
// Explicit formulas:
//
//       B = (X1+Y1)^2
//       C = X1^2
//       D = Y1^2
//       E = a*C
//       F = E+D
//       X3 = (B-C-D)*(F-2)
//       Y3 = F*(E-D)
//       Z3 = F^2-2*F
//
// This assumption is one reason why this package is internal. For instance, it
// will not hold throughout a Montgomery ladder, when we convert to projective
// from possibly arbitrary extended coordinates.
func (v *ProjectiveGroupElement) DoubleZ1(u *ProjectiveGroupElement) *ProjectiveGroupElement {
	var B, C, D, E, F radix51.FieldElement

	if u.Z.Equal(radix51.One) != 1 {
		panic("ed25519: DoubleZ1 called with Z != 1")
	}

	B.Square(B.Add(&u.X, &u.Y)) // B = (X1+Y1)^2
	C.Square(&u.X)              // C = X1^2
	D.Square(&u.Y)              // D = Y1^2
	E.Neg(&C)                   // E = a*C where a = -1
	F.Add(&E, &D)               // F = E + D

	// X3 = (B-C-D)*(F-2)
	v.Y.Sub(v.Y.Sub(&B, &C), &D)
	v.X.Mul(&v.Y, v.X.Sub(&F, radix51.Two))

	// Y3 = F*(E-D)
	v.Y.Mul(&F, v.Y.Sub(&E, &D))

	// Z3 = F^2 - 2*F
	v.Z.Square(&F)
	v.Z.Sub(&v.Z, &F)
	v.Z.Sub(&v.Z, &F)

	return v
}
