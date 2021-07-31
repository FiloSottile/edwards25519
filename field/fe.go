// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package field implements fast arithmetic modulo 2^255-19.
package field

import (
	"crypto/subtle"
	"errors"

	fiat "github.com/mit-plv/fiat-crypto/fiat-go/64/curve25519"
)

// Element represents an element of the field GF(2^255-19). Note that this
// is not a cryptographically secure group, and should only be used to interact
// with edwards25519.Point coordinates.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is a valid zero element.
type Element struct {
	limbs fiat.TightFieldElement
}

func newElementFromLimbs(l0, l1, l2, l3, l4 uint64) *Element {
	e := new(Element)
	fiat.Carry(&e.limbs, &fiat.LooseFieldElement{l0, l1, l2, l3, l4})
	return e
}

var feZero = newElementFromLimbs(0, 0, 0, 0, 0)

// Zero sets v = 0, and returns v.
func (v *Element) Zero() *Element {
	*v = *feZero
	return v
}

var feOne = newElementFromLimbs(1, 0, 0, 0, 0)

// One sets v = 1, and returns v.
func (v *Element) One() *Element {
	*v = *feOne
	return v
}

// Add sets v = a + b, and returns v.
func (v *Element) Add(a, b *Element) *Element {
	fiat.CarryAdd(&v.limbs, &a.limbs, &b.limbs)
	return v
}

// Subtract sets v = a - b, and returns v.
func (v *Element) Subtract(a, b *Element) *Element {
	fiat.CarrySub(&v.limbs, &a.limbs, &b.limbs)
	return v
}

// Negate sets v = -a, and returns v.
func (v *Element) Negate(a *Element) *Element {
	fiat.CarryOpp(&v.limbs, &a.limbs)
	return v
}

// Invert sets v = 1/z mod p, and returns v.
//
// If z == 0, Invert returns v = 0.
func (v *Element) Invert(z *Element) *Element {
	// Inversion is implemented as exponentiation with exponent p − 2. It uses the
	// same sequence of 255 squarings and 11 multiplications as [Curve25519].
	var z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t Element

	z2.Square(z)             // 2
	t.Square(&z2)            // 4
	t.Square(&t)             // 8
	z9.Multiply(&t, z)       // 9
	z11.Multiply(&z9, &z2)   // 11
	t.Square(&z11)           // 22
	z2_5_0.Multiply(&t, &z9) // 31 = 2^5 - 2^0

	t.Square(&z2_5_0) // 2^6 - 2^1
	for i := 0; i < 4; i++ {
		t.Square(&t) // 2^10 - 2^5
	}
	z2_10_0.Multiply(&t, &z2_5_0) // 2^10 - 2^0

	t.Square(&z2_10_0) // 2^11 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^20 - 2^10
	}
	z2_20_0.Multiply(&t, &z2_10_0) // 2^20 - 2^0

	t.Square(&z2_20_0) // 2^21 - 2^1
	for i := 0; i < 19; i++ {
		t.Square(&t) // 2^40 - 2^20
	}
	t.Multiply(&t, &z2_20_0) // 2^40 - 2^0

	t.Square(&t) // 2^41 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^50 - 2^10
	}
	z2_50_0.Multiply(&t, &z2_10_0) // 2^50 - 2^0

	t.Square(&z2_50_0) // 2^51 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^100 - 2^50
	}
	z2_100_0.Multiply(&t, &z2_50_0) // 2^100 - 2^0

	t.Square(&z2_100_0) // 2^101 - 2^1
	for i := 0; i < 99; i++ {
		t.Square(&t) // 2^200 - 2^100
	}
	t.Multiply(&t, &z2_100_0) // 2^200 - 2^0

	t.Square(&t) // 2^201 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^250 - 2^50
	}
	t.Multiply(&t, &z2_50_0) // 2^250 - 2^0

	t.Square(&t) // 2^251 - 2^1
	t.Square(&t) // 2^252 - 2^2
	t.Square(&t) // 2^253 - 2^3
	t.Square(&t) // 2^254 - 2^4
	t.Square(&t) // 2^255 - 2^5

	return v.Multiply(&t, &z11) // 2^255 - 21
}

// Set sets v = a, and returns v.
func (v *Element) Set(a *Element) *Element {
	*v = *a
	return v
}

// SetBytes sets v to x, where x is a 32-byte little-endian encoding. If x is
// not of the right length, SetBytes returns nil and an error, and the
// receiver is unchanged.
//
// Consistent with RFC 7748, the most significant bit (the high bit of the
// last byte) is ignored, and non-canonical values (2^255-19 through 2^255-1)
// are accepted. Note that this is laxer than specified by RFC 8032, but
// consistent with most Ed25519 implementations.
func (v *Element) SetBytes(x []byte) (*Element, error) {
	if len(x) != 32 {
		return nil, errors.New("edwards25519: invalid field element input size")
	}

	var xCopy [32]byte
	copy(xCopy[:], x)
	xCopy[31] &= 127 // Ignore the MSB

	fiat.FromBytes(&v.limbs, &xCopy)

	return v, nil
}

// Bytes returns the canonical 32-byte little-endian encoding of v.
func (v *Element) Bytes() []byte {
	var out [32]byte
	fiat.ToBytes(&out, &v.limbs)
	return out[:]
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *Element) Equal(u *Element) int {
	sa, sv := u.Bytes(), v.Bytes()
	return subtle.ConstantTimeCompare(sa, sv)
}

// mask64Bits returns 0xffffffff if cond is 1, and 0 otherwise.
func mask64Bits(cond int) uint64 { return ^(uint64(cond) - 1) }

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
	// fiat.Selectznz is unusable, due to the function prototype taking
	// an unexported type.  Performance isn't amazing either.
	m := mask64Bits(cond)
	v.limbs[0] = (m & a.limbs[0]) | (^m & b.limbs[0])
	v.limbs[1] = (m & a.limbs[1]) | (^m & b.limbs[1])
	v.limbs[2] = (m & a.limbs[2]) | (^m & b.limbs[2])
	v.limbs[3] = (m & a.limbs[3]) | (^m & b.limbs[3])
	v.limbs[4] = (m & a.limbs[4]) | (^m & b.limbs[4])
	return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0, and returns v.
func (v *Element) Swap(u *Element, cond int) {
	m := mask64Bits(cond)
	t := m & (v.limbs[0] ^ u.limbs[0])
	v.limbs[0] ^= t
	u.limbs[0] ^= t
	t = m & (v.limbs[1] ^ u.limbs[1])
	v.limbs[1] ^= t
	u.limbs[1] ^= t
	t = m & (v.limbs[2] ^ u.limbs[2])
	v.limbs[2] ^= t
	u.limbs[2] ^= t
	t = m & (v.limbs[3] ^ u.limbs[3])
	v.limbs[3] ^= t
	u.limbs[3] ^= t
	t = m & (v.limbs[4] ^ u.limbs[4])
	v.limbs[4] ^= t
	u.limbs[4] ^= t
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *Element) IsNegative() int {
	return int(v.Bytes()[0] & 1)
}

// Absolute sets v to |u|, and returns v.
func (v *Element) Absolute(u *Element) *Element {
	return v.Select(new(Element).Negate(u), u, u.IsNegative())
}

// Multiply sets v = x * y, and returns v.
func (v *Element) Multiply(x, y *Element) *Element {
	fiat.CarryMul(&v.limbs, (*fiat.LooseFieldElement)(&x.limbs), (*fiat.LooseFieldElement)(&y.limbs))
	return v
}

// Square sets v = x * x, and returns v.
func (v *Element) Square(x *Element) *Element {
	fiat.CarrySquare(&v.limbs, (*fiat.LooseFieldElement)(&x.limbs))
	return v
}

// Mult32 sets v = x * y, and returns v.
func (v *Element) Mult32(x *Element, y uint32) *Element {
	// fiat has CarryScmul121666 but nothing generic, do this the slow way
	// since the fast way + Carry voilates the bounds specified for
	// LooseFieldElement.
	yLimbs := fiat.LooseFieldElement{uint64(y), 0, 0, 0, 0}
	fiat.CarryMul(&v.limbs, (*fiat.LooseFieldElement)(&x.limbs), &yLimbs)
	return v
}

// Pow22523 set v = x^((p-5)/8), and returns v. (p-5)/8 is 2^252-3.
func (v *Element) Pow22523(x *Element) *Element {
	var t0, t1, t2 Element

	t0.Square(x)             // x^2
	t1.Square(&t0)           // x^4
	t1.Square(&t1)           // x^8
	t1.Multiply(x, &t1)      // x^9
	t0.Multiply(&t0, &t1)    // x^11
	t0.Square(&t0)           // x^22
	t0.Multiply(&t1, &t0)    // x^31
	t1.Square(&t0)           // x^62
	for i := 1; i < 5; i++ { // x^992
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)     // x^1023 -> 1023 = 2^10 - 1
	t1.Square(&t0)            // 2^11 - 2
	for i := 1; i < 10; i++ { // 2^20 - 2^10
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)     // 2^20 - 1
	t2.Square(&t1)            // 2^21 - 2
	for i := 1; i < 20; i++ { // 2^40 - 2^20
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)     // 2^40 - 1
	t1.Square(&t1)            // 2^41 - 2
	for i := 1; i < 10; i++ { // 2^50 - 2^10
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)     // 2^50 - 1
	t1.Square(&t0)            // 2^51 - 2
	for i := 1; i < 50; i++ { // 2^100 - 2^50
		t1.Square(&t1)
	}
	t1.Multiply(&t1, &t0)      // 2^100 - 1
	t2.Square(&t1)             // 2^101 - 2
	for i := 1; i < 100; i++ { // 2^200 - 2^100
		t2.Square(&t2)
	}
	t1.Multiply(&t2, &t1)     // 2^200 - 1
	t1.Square(&t1)            // 2^201 - 2
	for i := 1; i < 50; i++ { // 2^250 - 2^50
		t1.Square(&t1)
	}
	t0.Multiply(&t1, &t0)     // 2^250 - 1
	t0.Square(&t0)            // 2^251 - 2
	t0.Square(&t0)            // 2^252 - 4
	return v.Multiply(&t0, x) // 2^252 - 3 -> x^(2^252-3)
}

// sqrtM1 is 2^((p-1)/4), which squared is equal to -1 by Euler's Criterion.
var sqrtM1 = newElementFromLimbs(1718705420411056, 234908883556509,
	2233514472574048, 2117202627021982, 765476049583133)

// SqrtRatio sets r to the non-negative square root of the ratio of u and v.
//
// If u/v is square, SqrtRatio returns r and 1. If u/v is not square, SqrtRatio
// sets r according to Section 4.3 of draft-irtf-cfrg-ristretto255-decaf448-00,
// and returns r and 0.
func (r *Element) SqrtRatio(u, v *Element) (rr *Element, wasSquare int) {
	t0 := new(Element)

	// r = (u * v3) * (u * v7)^((p-5)/8)
	v2 := new(Element).Square(v)
	uv3 := new(Element).Multiply(u, t0.Multiply(v2, v))
	uv7 := new(Element).Multiply(uv3, t0.Square(v2))
	rr = new(Element).Multiply(uv3, t0.Pow22523(uv7))

	check := new(Element).Multiply(v, t0.Square(rr)) // check = v * r^2

	uNeg := new(Element).Negate(u)
	correctSignSqrt := check.Equal(u)
	flippedSignSqrt := check.Equal(uNeg)
	flippedSignSqrtI := check.Equal(t0.Multiply(uNeg, sqrtM1))

	rPrime := new(Element).Multiply(rr, sqrtM1) // r_prime = SQRT_M1 * r
	// r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
	rr.Select(rPrime, rr, flippedSignSqrt|flippedSignSqrtI)

	r.Absolute(rr) // Choose the nonnegative square root.
	return r, correctSignSqrt | flippedSignSqrt
}
