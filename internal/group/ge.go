// Implements group logic for the Ed25519 curve.

package group

import (
	"math/big"

	field "github.com/gtank/ed25519/internal/radix51"
)

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
	X, Y, Z, T field.FieldElement
}

// Converts (x,y) to (X:Y:T:Z) extended coordinates, or "P3" in ref10. As
// described in "Twisted Edwards Curves Revisited", Hisil-Wong-Carter-Dawson
// 2008, Section 3.1 (https://eprint.iacr.org/2008/522.pdf)
// See also https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
func (v *ExtendedGroupElement) FromAffine(x, y *big.Int) {
	field.FeFromBig(&v.X, x)
	field.FeFromBig(&v.Y, y)
	field.FeMul(&v.T, &v.X, &v.Y)
	field.FeOne(&v.Z)
}

// Extended coordinates are XYZT with x = X/Z, y = Y/Z, or the "P3"
// representation in ref10. Extended->affine is the same operation as moving
// from projective to affine. Per HWCD, it is safe to move from extended to
// projective by simply ignoring T.
func (v *ExtendedGroupElement) ToAffine() (*big.Int, *big.Int) {
	var x, y, zinv field.FieldElement

	field.FeInvert(&zinv, &v.Z)
	field.FeMul(&x, &v.X, &zinv)
	field.FeMul(&y, &v.Y, &zinv)

	return field.FeToBig(&x), field.FeToBig(&y)
}

// Per HWCD, it is safe to move from extended to projective by simply ignoring T.
func (v *ExtendedGroupElement) ToProjective() *ProjectiveGroupElement {
	var p ProjectiveGroupElement

	field.FeCopy(&p.X, &v.X)
	field.FeCopy(&p.Y, &v.Y)
	field.FeCopy(&p.Z, &v.Z)

	return &p
}

func (v *ExtendedGroupElement) Zero() *ExtendedGroupElement {
	field.FeZero(&v.X)
	field.FeOne(&v.Y)
	field.FeOne(&v.Z)
	field.FeZero(&v.T)
	return v
}

// This is the same addition formula everyone uses, "add-2008-hwcd-3".
// https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
// TODO We know Z1=1 and Z2=1 here, so mmadd-2008-hwcd-3 (6M + 1S + 1*k + 9add) could apply
func (v *ExtendedGroupElement) Add(p1, p2 *ExtendedGroupElement) *ExtendedGroupElement {
	var tmp1, tmp2, A, B, C, D, E, F, G, H field.FieldElement
	field.FeSub(&tmp1, &p1.Y, &p1.X) // tmp1 <-- Y1-X1
	field.FeSub(&tmp2, &p2.Y, &p2.X) // tmp2 <-- Y2-X2
	field.FeMul(&A, &tmp1, &tmp2)    // A <-- tmp1*tmp2 = (Y1-X1)*(Y2-X2)
	field.FeAdd(&tmp1, &p1.Y, &p1.X) // tmp1 <-- Y1+X1
	field.FeAdd(&tmp2, &p2.Y, &p2.X) // tmp2 <-- Y2+X2
	field.FeMul(&B, &tmp1, &tmp2)    // B <-- tmp1*tmp2 = (Y1+X1)*(Y2+X2)
	field.FeMul(&tmp1, &p1.T, &p2.T) // tmp1 <-- T1*T2
	field.FeMul(&C, &tmp1, &D2)      // C <-- tmp1*2d = T1*2d*T2
	field.FeMul(&tmp1, &p1.Z, &p2.Z) // tmp1 <-- Z1*Z2
	field.FeAdd(&D, &tmp1, &tmp1)    // D <-- tmp1 + tmp1 = 2*Z1*Z2
	field.FeSub(&E, &B, &A)          // E <-- B-A
	field.FeSub(&F, &D, &C)          // F <-- D-C
	field.FeAdd(&G, &D, &C)          // G <-- D+C
	field.FeAdd(&H, &B, &A)          // H <-- B+A
	field.FeMul(&v.X, &E, &F)        // X3 <-- E*F
	field.FeMul(&v.Y, &G, &H)        // Y3 <-- G*H
	field.FeMul(&v.T, &E, &H)        // T3 <-- E*H
	field.FeMul(&v.Z, &F, &G)        // Z3 <-- F*G
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
func (v *ExtendedGroupElement) Double() *ExtendedGroupElement {
	// TODO: Convert to projective coordinates? Section 4.3 mixed doubling?
	// TODO: make a decision about how these APIs work wrt chaining/smashing
	// *v = *(v.ToProjective().Double().ToExtended())
	// return v

	var A, B, C, D, E, F, G, H field.FieldElement

	// A ← X1^2, B ← Y1^2
	field.FeSquare(&A, &v.X)
	field.FeSquare(&B, &v.Y)

	// C ← 2*Z1^2
	field.FeSquare(&C, &v.Z)
	field.FeAdd(&C, &C, &C) // TODO should probably implement FeSquare2

	// D ← -1*A
	field.FeNeg(&D, &A) // implemented as substraction

	// E ← (X1+Y1)^2 − A − B
	var t0 field.FieldElement
	field.FeAdd(&t0, &v.X, &v.Y)
	field.FeSquare(&t0, &t0)
	field.FeSub(&E, &t0, &A)
	field.FeSub(&E, &E, &B)

	// G ← D+B
	field.FeAdd(&G, &D, &B)
	// F ← G−C
	field.FeSub(&F, &G, &C)
	// H ← D−B
	field.FeSub(&H, &D, &B)
	// X3 ← E*F
	field.FeMul(&v.X, &E, &F)
	// Y3 ← G*H
	field.FeMul(&v.Y, &G, &H)
	// T3 ← E*H
	field.FeMul(&v.T, &E, &H)
	// Z3 ← F*G
	field.FeMul(&v.Z, &F, &G)

	return v
}

// Projective coordinates are XYZ with x = X/Z, y = Y/Z, or the "P2"
// representation in ref10. This representation has a cheaper doubling formula
// than extended coordinates.
type ProjectiveGroupElement struct {
	X, Y, Z field.FieldElement
}

func (v *ProjectiveGroupElement) FromAffine(x, y *big.Int) {
	field.FeFromBig(&v.X, x)
	field.FeFromBig(&v.Y, y)
	field.FeOne(&v.Z)
}

func (v *ProjectiveGroupElement) ToAffine() (*big.Int, *big.Int) {
	var x, y, zinv field.FieldElement

	field.FeInvert(&zinv, &v.Z)
	field.FeMul(&x, &v.X, &zinv)
	field.FeMul(&y, &v.Y, &zinv)

	return field.FeToBig(&x), field.FeToBig(&y)
}

// HWCD Section 3: "Given (X : Y : Z) in [projective coordinates] passing to
// [extended coordinates, (X : Y : T : Z)] can be performed in 3M+1S by computing
// (XZ, YZ, XY, Z^2)"
func (v *ProjectiveGroupElement) ToExtended() *ExtendedGroupElement {
	var r ExtendedGroupElement

	field.FeMul(&r.X, &v.X, &v.Z)
	field.FeMul(&r.Y, &v.Y, &v.Z)
	field.FeMul(&r.T, &v.X, &v.Y)
	field.FeSquare(&r.Z, &v.Z)

	return &r
}

func (v *ProjectiveGroupElement) Zero() *ProjectiveGroupElement {
	field.FeZero(&v.X)
	field.FeOne(&v.Y)
	field.FeOne(&v.Z)
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
func (v *ProjectiveGroupElement) DoubleZ1() *ProjectiveGroupElement {
	// TODO This function is inconsistent with the other ones in that it
	// returns a copy rather than smashing the receiver. It doesn't matter
	// because it is always called on ephemeral intermediate values, but should
	// fix.
	var p, q ProjectiveGroupElement
	var t0, t1 field.FieldElement

	p = *v

	// C = X1^2, D = Y1^2
	field.FeSquare(&t0, &p.X)
	field.FeSquare(&t1, &p.Y)

	// B = (X1+Y1)^2
	field.FeAdd(&p.Z, &p.X, &p.Y) // Z is irrelevant but already allocated
	field.FeSquare(&q.X, &p.Z)

	// E = a*C where a = -1
	field.FeNeg(&q.Z, &t0)

	// F = E + D
	field.FeAdd(&p.X, &q.Z, &t1)

	// X3 = (B-C-D)*(F-2)
	field.FeSub(&p.Y, &q.X, &t0)
	field.FeSub(&p.Y, &p.Y, &t1)
	field.FeSub(&p.Z, &p.X, &field.FieldTwo)
	field.FeMul(&q.X, &p.Y, &p.Z)

	// Y3 = F*(E-D)
	field.FeSub(&p.Y, &q.Z, &t1)
	field.FeMul(&q.Y, &p.X, &p.Y)

	// Z3 = F^2 - 2*F
	field.FeSquare(&q.Z, &p.X)
	field.FeSub(&q.Z, &q.Z, &p.X)
	field.FeSub(&q.Z, &q.Z, &p.X)

	return &q
}
