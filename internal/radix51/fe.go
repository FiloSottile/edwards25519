// Copyright (c) 2017 George Tankersley. All rights reserved.
// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Field arithmetic in radix 2^51 representation. This code is a port of the
// public domain amd64-51-30k version of ed25519 from SUPERCOP.
package radix51

import (
	"crypto/subtle"
	"math/big"
	"math/bits"
)

// FieldElement represents an element of the field GF(2^255-19). An element t
// represents the integer t[0] + t[1]*2^51 + t[2]*2^102 + t[3]*2^153 +
// t[4]*2^204. The zero value is a valid zero element.
type FieldElement [5]uint64

const (
	// The vaule 2^51-1, used in carry propagation
	maskLow51Bits = uint64(1)<<51 - 1
)

var (
	Zero     = &FieldElement{0, 0, 0, 0, 0}
	One      = &FieldElement{1, 0, 0, 0, 0}
	Two      = &FieldElement{2, 0, 0, 0, 0}
	MinusOne = new(FieldElement).Neg(One)
)

func (v *FieldElement) Zero() *FieldElement {
	v[0] = 0
	v[1] = 0
	v[2] = 0
	v[3] = 0
	v[4] = 0
	return v
}

func (v *FieldElement) One() *FieldElement {
	v[0] = 1
	v[1] = 0
	v[2] = 0
	v[3] = 0
	v[4] = 0
	return v
}

// SetInt sets the receiving FieldElement to the specified small integer.
func (v *FieldElement) SetInt(x uint64) *FieldElement {
	v[0] = x
	v[1] = 0
	v[2] = 0
	v[3] = 0
	v[4] = 0
	return v
}

func (v *FieldElement) Reduce(u *FieldElement) *FieldElement {
	v.Set(u)

	// Lev v = v[0] + v[1]*2^51 + v[2]*2^102 + v[3]*2^153 + v[4]*2^204
	// Reduce each limb below 2^51, propagating carries.
	v[1] += v[0] >> 51
	v[0] = v[0] & maskLow51Bits
	v[2] += v[1] >> 51
	v[1] = v[1] & maskLow51Bits
	v[3] += v[2] >> 51
	v[2] = v[2] & maskLow51Bits
	v[4] += v[3] >> 51
	v[3] = v[3] & maskLow51Bits
	v[0] += (v[4] >> 51) * 19
	v[4] = v[4] & maskLow51Bits

	// We now hate a field element v < 2^255, but need v <= 2^255-19
	// TODO Document why this works. It's the elaborate comment about r = h-pq etc etc.

	// Get the carry bit
	c := (v[0] + 19) >> 51
	c = (v[1] + c) >> 51
	c = (v[2] + c) >> 51
	c = (v[3] + c) >> 51
	c = (v[4] + c) >> 51

	v[0] += 19 * c

	v[1] += v[0] >> 51
	v[0] = v[0] & maskLow51Bits
	v[2] += v[1] >> 51
	v[1] = v[1] & maskLow51Bits
	v[3] += v[2] >> 51
	v[2] = v[2] & maskLow51Bits
	v[4] += v[3] >> 51
	v[3] = v[3] & maskLow51Bits
	// no additional carry
	v[4] = v[4] & maskLow51Bits

	return v
}

// Add sets v = a + b. Long sequences of additions without reduction that
// let coefficients grow larger than 54 bits would be a problem. Paper
// cautions: "do not have such sequences of additions".
func (v *FieldElement) Add(a, b *FieldElement) *FieldElement {
	v[0] = a[0] + b[0]
	v[1] = a[1] + b[1]
	v[2] = a[2] + b[2]
	v[3] = a[3] + b[3]
	v[4] = a[4] + b[4]
	return v
}

// Sub sets v = a - b.
func (v *FieldElement) Sub(a, b *FieldElement) *FieldElement {
	t := *b

	// Reduce each limb below 2^51, propagating carries. Ensures that results
	// fit within the limbs. This would not be required for reduced input.
	t[1] += t[0] >> 51
	t[0] = t[0] & maskLow51Bits
	t[2] += t[1] >> 51
	t[1] = t[1] & maskLow51Bits
	t[3] += t[2] >> 51
	t[2] = t[2] & maskLow51Bits
	t[4] += t[3] >> 51
	t[3] = t[3] & maskLow51Bits
	t[0] += (t[4] >> 51) * 19
	t[4] = t[4] & maskLow51Bits

	// This is slightly more complicated. Because we use unsigned coefficients, we
	// first add a multiple of p and then subtract.
	v[0] = (a[0] + 0xFFFFFFFFFFFDA) - t[0]
	v[1] = (a[1] + 0xFFFFFFFFFFFFE) - t[1]
	v[2] = (a[2] + 0xFFFFFFFFFFFFE) - t[2]
	v[3] = (a[3] + 0xFFFFFFFFFFFFE) - t[3]
	v[4] = (a[4] + 0xFFFFFFFFFFFFE) - t[4]

	return v
}

// Neg sets v = -a.
func (v *FieldElement) Neg(a *FieldElement) *FieldElement {
	return v.Sub(Zero, a)
}

// Invert sets v = 1/z mod p by calculating z^(p-2), p-2 = 2^255 - 21.
func (v *FieldElement) Invert(z *FieldElement) *FieldElement {
	// Inversion is implemented as exponentiation with exponent p − 2. It uses the
	// same sequence of 255 squarings and 11 multiplications as [Curve25519].
	var z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t FieldElement

	z2.Square(z)        // 2
	t.Square(&z2)       // 4
	t.Square(&t)        // 8
	z9.Mul(&t, z)       // 9
	z11.Mul(&z9, &z2)   // 11
	t.Square(&z11)      // 22
	z2_5_0.Mul(&t, &z9) // 2^5 - 2^0 = 31

	t.Square(&z2_5_0) // 2^6 - 2^1
	for i := 0; i < 4; i++ {
		t.Square(&t) // 2^10 - 2^5
	}
	z2_10_0.Mul(&t, &z2_5_0) // 2^10 - 2^0

	t.Square(&z2_10_0) // 2^11 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^20 - 2^10
	}
	z2_20_0.Mul(&t, &z2_10_0) // 2^20 - 2^0

	t.Square(&z2_20_0) // 2^21 - 2^1
	for i := 0; i < 19; i++ {
		t.Square(&t) // 2^40 - 2^20
	}
	t.Mul(&t, &z2_20_0) // 2^40 - 2^0

	t.Square(&t) // 2^41 - 2^1
	for i := 0; i < 9; i++ {
		t.Square(&t) // 2^50 - 2^10
	}
	z2_50_0.Mul(&t, &z2_10_0) // 2^50 - 2^0

	t.Square(&z2_50_0) // 2^51 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^100 - 2^50
	}
	z2_100_0.Mul(&t, &z2_50_0) // 2^100 - 2^0

	t.Square(&z2_100_0) // 2^101 - 2^1
	for i := 0; i < 99; i++ {
		t.Square(&t) // 2^200 - 2^100
	}
	t.Mul(&t, &z2_100_0) // 2^200 - 2^0

	t.Square(&t) // 2^201 - 2^1
	for i := 0; i < 49; i++ {
		t.Square(&t) // 2^250 - 2^50
	}
	t.Mul(&t, &z2_50_0) // 2^250 - 2^0

	t.Square(&t) // 2^251 - 2^1
	t.Square(&t) // 2^252 - 2^2
	t.Square(&t) // 2^253 - 2^3
	t.Square(&t) // 2^254 - 2^4
	t.Square(&t) // 2^255 - 2^5

	return v.Mul(&t, &z11) // 2^255 - 21
}

func (v *FieldElement) Set(a *FieldElement) *FieldElement {
	*v = *a
	return v
}

func (v *FieldElement) FromBytes(x []byte) *FieldElement {
	if len(x) != 32 {
		panic("invalid input size")
	}
	v[0] = uint64(x[0])
	v[0] |= uint64(x[1]) << 8
	v[0] |= uint64(x[2]) << 16
	v[0] |= uint64(x[3]) << 24
	v[0] |= uint64(x[4]) << 32
	v[0] |= uint64(x[5]) << 40
	v[0] |= uint64(x[6]&7) << 48

	v[1] = uint64(x[6]) >> 3
	v[1] |= uint64(x[7]) << 5
	v[1] |= uint64(x[8]) << 13
	v[1] |= uint64(x[9]) << 21
	v[1] |= uint64(x[10]) << 29
	v[1] |= uint64(x[11]) << 37
	v[1] |= uint64(x[12]&63) << 45

	v[2] = uint64(x[12]) >> 6
	v[2] |= uint64(x[13]) << 2
	v[2] |= uint64(x[14]) << 10
	v[2] |= uint64(x[15]) << 18
	v[2] |= uint64(x[16]) << 26
	v[2] |= uint64(x[17]) << 34
	v[2] |= uint64(x[18]) << 42
	v[2] |= uint64(x[19]&1) << 50

	v[3] = uint64(x[19]) >> 1
	v[3] |= uint64(x[20]) << 7
	v[3] |= uint64(x[21]) << 15
	v[3] |= uint64(x[22]) << 23
	v[3] |= uint64(x[23]) << 31
	v[3] |= uint64(x[24]) << 39
	v[3] |= uint64(x[25]&15) << 47

	v[4] = uint64(x[25]) >> 4
	v[4] |= uint64(x[26]) << 4
	v[4] |= uint64(x[27]) << 12
	v[4] |= uint64(x[28]) << 20
	v[4] |= uint64(x[29]) << 28
	v[4] |= uint64(x[30]) << 36
	v[4] |= uint64(x[31]&127) << 44

	return v
}

func (v *FieldElement) ToBytes(r []byte) {
	if len(r) != 32 {
		panic("invalid input size")
	}
	t := new(FieldElement).Reduce(v)

	r[0] = byte(t[0] & 0xff)
	r[1] = byte((t[0] >> 8) & 0xff)
	r[2] = byte((t[0] >> 16) & 0xff)
	r[3] = byte((t[0] >> 24) & 0xff)
	r[4] = byte((t[0] >> 32) & 0xff)
	r[5] = byte((t[0] >> 40) & 0xff)
	r[6] = byte((t[0] >> 48))

	r[6] ^= byte((t[1] << 3) & 0xf8)
	r[7] = byte((t[1] >> 5) & 0xff)
	r[8] = byte((t[1] >> 13) & 0xff)
	r[9] = byte((t[1] >> 21) & 0xff)
	r[10] = byte((t[1] >> 29) & 0xff)
	r[11] = byte((t[1] >> 37) & 0xff)
	r[12] = byte((t[1] >> 45))

	r[12] ^= byte((t[2] << 6) & 0xc0)
	r[13] = byte((t[2] >> 2) & 0xff)
	r[14] = byte((t[2] >> 10) & 0xff)
	r[15] = byte((t[2] >> 18) & 0xff)
	r[16] = byte((t[2] >> 26) & 0xff)
	r[17] = byte((t[2] >> 34) & 0xff)
	r[18] = byte((t[2] >> 42) & 0xff)
	r[19] = byte((t[2] >> 50))

	r[19] ^= byte((t[3] << 1) & 0xfe)
	r[20] = byte((t[3] >> 7) & 0xff)
	r[21] = byte((t[3] >> 15) & 0xff)
	r[22] = byte((t[3] >> 23) & 0xff)
	r[23] = byte((t[3] >> 31) & 0xff)
	r[24] = byte((t[3] >> 39) & 0xff)
	r[25] = byte((t[3] >> 47))

	r[25] ^= byte((t[4] << 4) & 0xf0)
	r[26] = byte((t[4] >> 4) & 0xff)
	r[27] = byte((t[4] >> 12) & 0xff)
	r[28] = byte((t[4] >> 20) & 0xff)
	r[29] = byte((t[4] >> 28) & 0xff)
	r[30] = byte((t[4] >> 36) & 0xff)
	r[31] = byte((t[4] >> 44))
}

func (v *FieldElement) FromBig(num *big.Int) *FieldElement {
	var buf [32]byte

	offset := 0
	words := num.Bits()
	numWords := len(words)

	for n := 0; n < numWords; n++ {
		word := words[n]
		for i := 0; i < bits.UintSize/8; i++ {
			if offset >= len(buf) {
				break
			}
			buf[offset] = byte(word >> uint((i << 3)))
			offset++
		}
	}

	return v.FromBytes(buf[:])
}

func (v *FieldElement) ToBig() *big.Int {
	var buf [32]byte
	v.ToBytes(buf[:]) // does a reduction

	numWords := 256 / bits.UintSize
	words := make([]big.Word, numWords)

	offset := 0
	byteSize := uint(bits.UintSize >> 3)
	for n := 0; n < numWords; n++ {
		word := uint(0)
		for i := uint(0); i < byteSize; i++ {
			if offset >= len(buf) {
				break
			}
			word |= uint(buf[offset]) << (i << 3)
			offset++
		}
		words[n] = big.Word(word)
	}

	out := new(big.Int)
	return out.SetBits(words)
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *FieldElement) Equal(u *FieldElement) int {
	var sa, sv [32]byte
	u.ToBytes(sa[:])
	v.ToBytes(sv[:])
	return subtle.ConstantTimeCompare(sa[:], sv[:])
}

const mask64Bits uint64 = (1 << 64) - 1

// Select sets v to a if cond == 1, and to b if cond == 0.
// v, a and b are allowed to overlap.
func (v *FieldElement) Select(a, b *FieldElement, cond int) *FieldElement {
	m := uint64(cond) * mask64Bits
	v[0] = (m & a[0]) | (^m & b[0])
	v[1] = (m & a[1]) | (^m & b[1])
	v[2] = (m & a[2]) | (^m & b[2])
	v[3] = (m & a[3]) | (^m & b[3])
	v[4] = (m & a[4]) | (^m & b[4])
	return v
}

// CondNeg sets v to -u if cond == 1, and to u if cond == 0.
func (v *FieldElement) CondNeg(u *FieldElement, cond int) *FieldElement {
	return v.Select(v.Neg(u), u, cond)
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *FieldElement) IsNegative() int {
	var b [32]byte
	v.ToBytes(b[:])
	return int(b[0] & 1)
}

// Abs sets v to |u|. v and u are allowed to overlap.
func (v *FieldElement) Abs(u *FieldElement) *FieldElement {
	return v.CondNeg(u, u.IsNegative())
}
