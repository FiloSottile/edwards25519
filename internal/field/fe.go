// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package field

import (
	"crypto/subtle"
	"encoding/binary"
)

// Element represents an element of the field GF(2^255-19). Note that this
// is not a cryptographically secure group, and should only be used to interact
// with Point coordinates.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is a valid zero element.
type Element struct {
	// An element t represents the integer
	//     t.L0 + t.L1*2^51 + t.L2*2^102 + t.L3*2^153 + t.L4*2^204
	//
	// Between operations, all limbs are expected to be lower than 2^52.
	L0, L1, L2, L3, L4 uint64
}

const maskLow51Bits uint64 = (1 << 51) - 1

var (
	zero     = &Element{0, 0, 0, 0, 0}
	one      = &Element{1, 0, 0, 0, 0}
	two      = &Element{2, 0, 0, 0, 0}
	minusOne = new(Element).Negate(one)
)

// Zero sets v = 0, and returns v.
func (v *Element) Zero() *Element {
	*v = *zero
	return v
}

// One sets v = 1, and returns v.
func (v *Element) One() *Element {
	*v = *one
	return v
}

// reduce reduces v modulo 2^255 - 19 and returns it.
func (v *Element) reduce() *Element {
	v.carryPropagate()

	// After the light reduction we now have a field element representation
	// v < 2^255 + 2^13 * 19, but need v < 2^255 - 19.

	// If v >= 2^255 - 19, then v + 19 >= 2^255, which would overflow 2^255 - 1,
	// generating a carry. That is, c will be 0 if v < 2^255 - 19, and 1 otherwise.
	c := (v.L0 + 19) >> 51
	c = (v.L1 + c) >> 51
	c = (v.L2 + c) >> 51
	c = (v.L3 + c) >> 51
	c = (v.L4 + c) >> 51

	// If v < 2^255 - 19 and c = 0, this will be a no-op. Otherwise, it's
	// effectively applying the reduction identity to the carry.
	v.L0 += 19 * c

	v.L1 += v.L0 >> 51
	v.L0 = v.L0 & maskLow51Bits
	v.L2 += v.L1 >> 51
	v.L1 = v.L1 & maskLow51Bits
	v.L3 += v.L2 >> 51
	v.L2 = v.L2 & maskLow51Bits
	v.L4 += v.L3 >> 51
	v.L3 = v.L3 & maskLow51Bits
	// no additional carry
	v.L4 = v.L4 & maskLow51Bits

	return v
}

// Add sets v = a + b, and returns v.
func (v *Element) Add(a, b *Element) *Element {
	v.L0 = a.L0 + b.L0
	v.L1 = a.L1 + b.L1
	v.L2 = a.L2 + b.L2
	v.L3 = a.L3 + b.L3
	v.L4 = a.L4 + b.L4
	// Using the generic implementation here is actually faster than the
	// assembly. Probably because the body of this function is so simple that
	// the compiler can figure out better optimizations by inlining the carry.
	return v.carryPropagateGeneric()
}

// Subtract sets v = a - b, and returns v.
func (v *Element) Subtract(a, b *Element) *Element {
	// We first add 2 * p, to guarantee the subtraction won't underflow, and
	// then subtract b (which can be up to 2^255 + 2^13 * 19).
	v.L0 = (a.L0 + 0xFFFFFFFFFFFDA) - b.L0
	v.L1 = (a.L1 + 0xFFFFFFFFFFFFE) - b.L1
	v.L2 = (a.L2 + 0xFFFFFFFFFFFFE) - b.L2
	v.L3 = (a.L3 + 0xFFFFFFFFFFFFE) - b.L3
	v.L4 = (a.L4 + 0xFFFFFFFFFFFFE) - b.L4
	return v.carryPropagate()
}

// Negate sets v = -a, and returns v.
func (v *Element) Negate(a *Element) *Element {
	return v.Subtract(zero, a)
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
	z2_5_0.Multiply(&t, &z9) // 2^5 - 2^0 = 31

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

// SetBytes sets v to x, which must be a 32 bytes little-endian encoding.
//
// Consistently with RFC 7748, the most significant bit (the high bit of the
// last byte) is ignored, and non-canonical values (2^255-19 through 2^255-1)
// are accepted. Note that this is laxer than specified by RFC 8032.
func (v *Element) SetBytes(x []byte) *Element {
	if len(x) != 32 {
		panic("edwards25519: invalid field element input size")
	}

	// Bits 0:51 (bytes 0:8, bits 0:64, shift 0, mask 51).
	v.L0 = binary.LittleEndian.Uint64(x[0:8])
	v.L0 &= maskLow51Bits
	// Bits 51:102 (bytes 6:14, bits 48:112, shift 3, mask 51).
	v.L1 = binary.LittleEndian.Uint64(x[6:14]) >> 3
	v.L1 &= maskLow51Bits
	// Bits 102:153 (bytes 12:20, bits 96:160, shift 6, mask 51).
	v.L2 = binary.LittleEndian.Uint64(x[12:20]) >> 6
	v.L2 &= maskLow51Bits
	// Bits 153:204 (bytes 19:27, bits 152:216, shift 1, mask 51).
	v.L3 = binary.LittleEndian.Uint64(x[19:27]) >> 1
	v.L3 &= maskLow51Bits
	// Bits 204:251 (bytes 24:32, bits 192:256, shift 12, mask 51).
	// Note: not bytes 25:33, shift 4, to avoid overread.
	v.L4 = binary.LittleEndian.Uint64(x[24:32]) >> 12
	v.L4 &= maskLow51Bits

	return v
}

// Bytes returns the canonical 32 bytes little-endian encoding of v.
func (v *Element) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [32]byte
	return v.bytes(&out)
}

func (v *Element) bytes(out *[32]byte) []byte {
	t := *v
	t.reduce()

	var buf [8]byte
	for i, l := range [5]uint64{t.L0, t.L1, t.L2, t.L3, t.L4} {
		bitsOffset := i * 51
		binary.LittleEndian.PutUint64(buf[:], l<<uint(bitsOffset%8))
		for i, bb := range buf {
			off := bitsOffset/8 + i
			if off >= len(out) {
				break
			}
			out[off] |= bb
		}
	}

	return out[:]
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *Element) Equal(u *Element) int {
	sa, sv := u.Bytes(), v.Bytes()
	return subtle.ConstantTimeCompare(sa, sv)
}

const mask64Bits uint64 = (1 << 64) - 1

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
	m := uint64(cond) * mask64Bits
	v.L0 = (m & a.L0) | (^m & b.L0)
	v.L1 = (m & a.L1) | (^m & b.L1)
	v.L2 = (m & a.L2) | (^m & b.L2)
	v.L3 = (m & a.L3) | (^m & b.L3)
	v.L4 = (m & a.L4) | (^m & b.L4)
	return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0, and returns v.
func (v *Element) Swap(u *Element, cond int) {
	m := uint64(cond) * mask64Bits
	t := m & (v.L0 ^ u.L0)
	v.L0 ^= t
	u.L0 ^= t
	t = m & (v.L1 ^ u.L1)
	v.L1 ^= t
	u.L1 ^= t
	t = m & (v.L2 ^ u.L2)
	v.L2 ^= t
	u.L2 ^= t
	t = m & (v.L3 ^ u.L3)
	v.L3 ^= t
	u.L3 ^= t
	t = m & (v.L4 ^ u.L4)
	v.L4 ^= t
	u.L4 ^= t
}

// CondNegate sets v to -u if cond == 1, and to u if cond == 0.
func (v *Element) CondNegate(u *Element, cond int) *Element {
	tmp := new(Element).Negate(u)
	return v.Select(tmp, u, cond)
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *Element) IsNegative() int {
	b := v.Bytes()
	return int(b[0] & 1)
}

// Absolute sets v to |u|, and returns v.
func (v *Element) Absolute(u *Element) *Element {
	return v.CondNegate(u, u.IsNegative())
}

// Multiply sets v = x * y, and returns v.
func (v *Element) Multiply(x, y *Element) *Element {
	feMul(v, x, y)
	return v
}

// Square sets v = x * x, and returns v.
func (v *Element) Square(x *Element) *Element {
	feSquare(v, x)
	return v
}

// Mult32 sets v = x * y, and returns v.
func (v *Element) Mult32(x *Element, y uint32) *Element {
	x0lo, x0hi := mul51(x.L0, y)
	x1lo, x1hi := mul51(x.L1, y)
	x2lo, x2hi := mul51(x.L2, y)
	x3lo, x3hi := mul51(x.L3, y)
	x4lo, x4hi := mul51(x.L4, y)
	v.L0 = x0lo + 19*x4hi // carried over per the reduction identity
	v.L1 = x1lo + x0hi
	v.L2 = x2lo + x1hi
	v.L3 = x3lo + x2hi
	v.L4 = x4lo + x3hi
	// The hi portions are going to be only 32 bits, plus any previous excess,
	// so we can skip the carry propagation.
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
var sqrtM1 = &Element{1718705420411056, 234908883556509,
	2233514472574048, 2117202627021982, 765476049583133}

// SqrtRatio sets r to the non-negative square root of the ratio of u and v.
//
// If u/v is square, SqrtRatio returns r and 1. If u/v is not square, SqrtRatio
// sets r according to Section 4.3 of draft-irtf-cfrg-ristretto255-decaf448-00,
// and returns r and 0.
func (r *Element) SqrtRatio(u, v *Element) (rr *Element, wasSquare int) {
	var a, b Element

	// r = (u * v3) * (u * v7)^((p-5)/8)
	v2 := a.Square(v)
	uv3 := b.Multiply(u, b.Multiply(v2, v))
	uv7 := a.Multiply(uv3, a.Square(v2))
	r.Multiply(uv3, r.Pow22523(uv7))

	check := a.Multiply(v, a.Square(r)) // check = v * r^2

	uNeg := b.Negate(u)
	correctSignSqrt := check.Equal(u)
	flippedSignSqrt := check.Equal(uNeg)
	flippedSignSqrtI := check.Equal(uNeg.Multiply(uNeg, sqrtM1))

	rPrime := b.Multiply(r, sqrtM1) // r_prime = SQRT_M1 * r
	// r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
	r.Select(rPrime, r, flippedSignSqrt|flippedSignSqrtI)

	r.Absolute(r) // Choose the nonnegative square root.
	return r, correctSignSqrt | flippedSignSqrt
}
