// Copyright (c) 2017 George Tankersley. All rights reserved.
// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// GF(2^255-19) field arithmetic in radix 2^51 representation. This code is a
// port of the public domain amd64-51-30k version of ed25519 from SUPERCOP.
//
// The interface works similarly to math/big.Int, and all arguments and
// receivers are allowed to alias.
package radix51

import (
	"crypto/subtle"
	"encoding/binary"
	"math/big"
	"math/bits"
)

// FieldElement represents an element of the field GF(2^255-19). An element t
// represents the integer t[0] + t[1]*2^51 + t[2]*2^102 + t[3]*2^153 +
// t[4]*2^204. Each limb must not exceed 2^54 - 1 to be valid.
//
// The zero value is a valid zero element.
type FieldElement [5]uint64

const maskLow51Bits uint64 = (1 << 51) - 1

var (
	Zero     = &FieldElement{0, 0, 0, 0, 0}
	One      = &FieldElement{1, 0, 0, 0, 0}
	Two      = &FieldElement{2, 0, 0, 0, 0}
	MinusOne = new(FieldElement).Neg(One)
)

// Zero sets v = 0 and returns v.
func (v *FieldElement) Zero() *FieldElement {
	v[0] = 0
	v[1] = 0
	v[2] = 0
	v[3] = 0
	v[4] = 0
	return v
}

// One sets v = 1 and returns v.
func (v *FieldElement) One() *FieldElement {
	v[0] = 1
	v[1] = 0
	v[2] = 0
	v[3] = 0
	v[4] = 0
	return v
}

// Reduce reduces v modulo 2^255 - 19 and returns it.
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

// Add sets v = a + b and returns v.
//
// Long sequences of additions without reduction that let coefficients grow
// larger than 54 bits would be a problem. Paper cautions: "do not have such
// sequences of additions".
func (v *FieldElement) Add(a, b *FieldElement) *FieldElement {
	v[0] = a[0] + b[0]
	v[1] = a[1] + b[1]
	v[2] = a[2] + b[2]
	v[3] = a[3] + b[3]
	v[4] = a[4] + b[4]
	return v
}

// Sub sets v = a - b and returns v.
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

// Neg sets v = -a and returns v.
func (v *FieldElement) Neg(a *FieldElement) *FieldElement {
	return v.Sub(Zero, a)
}

// Invert sets v = 1/z mod p and returns v.
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

// Set sets v = a and returns v.
func (v *FieldElement) Set(a *FieldElement) *FieldElement {
	*v = *a
	return v
}

// FromBytes sets v to x, which must be a 32 bytes little-endian encoding.
//
// Consistently with RFC 7748, the most significant bit (the high bit of the
// last byte) is ignored, and non-canonical values (2^255-19 through 2^255-1)
// are accepted.
func (v *FieldElement) FromBytes(x []byte) *FieldElement {
	if len(x) != 32 {
		panic("ed25519: invalid field element input size")
	}

	// Provide headroom for the slight binary.LittleEndian.Uint64 overread. (We
	// read 64 bits at an offset of 200, but then take only 4+51 into account.)
	var buf [33]byte
	copy(buf[:], x)

	for i := range v {
		bitsOffset := i * 51
		v[i] = binary.LittleEndian.Uint64(buf[bitsOffset/8:])
		v[i] >>= uint(bitsOffset % 8)
		v[i] &= maskLow51Bits
	}

	return v
}

// Bytes appends a 32 bytes little-endian encoding of v to b.
func (v *FieldElement) Bytes(b []byte) []byte {
	t := new(FieldElement).Reduce(v)

	res, out := sliceForAppend(b, 32)
	for i := range out {
		out[i] = 0
	}

	var buf [8]byte
	for i := range t {
		bitsOffset := i * 51
		binary.LittleEndian.PutUint64(buf[:], t[i]<<uint(bitsOffset%8))
		for i, b := range buf {
			off := bitsOffset/8 + i
			if off >= len(out) {
				break
			}
			out[off] |= b
		}
	}

	return res
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// FromBig sets v = n and returns v. The bit length of n must not exceed 256.
func (v *FieldElement) FromBig(n *big.Int) *FieldElement {
	if n.BitLen() > 32*8 {
		panic("ed25519: invalid field element input size")
	}

	buf := make([]byte, 0, 32)
	for _, word := range n.Bits() {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) >= cap(buf) {
				break
			}
			buf = append(buf, byte(word))
			word >>= 8
		}
	}

	return v.FromBytes(buf[:32])
}

// ToBig returns v as a big.Int.
func (v *FieldElement) ToBig() *big.Int {
	buf := v.Bytes(nil)

	words := make([]big.Word, 32*8/bits.UintSize)
	for n := range words {
		for i := 0; i < bits.UintSize; i += 8 {
			if len(buf) == 0 {
				break
			}
			words[n] |= big.Word(buf[0]) << big.Word(i)
			buf = buf[1:]
		}
	}

	return new(big.Int).SetBits(words)
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *FieldElement) Equal(u *FieldElement) int {
	var sa, sv [32]byte
	u.Bytes(sa[:0])
	v.Bytes(sv[:0])
	return subtle.ConstantTimeCompare(sa[:], sv[:])
}

const mask64Bits uint64 = (1 << 64) - 1

// Select sets v to a if cond == 1, and to b if cond == 0.
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
	tmp := new(FieldElement).Neg(u)
	return v.Select(tmp, u, cond)
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *FieldElement) IsNegative() int {
	var b [32]byte
	v.Bytes(b[:0])
	return int(b[0] & 1)
}

// Abs sets v to |u| and returns v.
func (v *FieldElement) Abs(u *FieldElement) *FieldElement {
	return v.CondNeg(u, u.IsNegative())
}
