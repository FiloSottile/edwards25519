// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func (v fieldElement) String() string {
	return hex.EncodeToString(v.Bytes())
}

// quickCheckConfig1024 will make each quickcheck test run (1024 * -quickchecks)
// times. The default value of -quickchecks is 100.
var quickCheckConfig1024 = &quick.Config{MaxCountScale: 1 << 10}

func generateFieldElement(rand *mathrand.Rand) fieldElement {
	// Generation strategy: generate random limb values of [52, 51, 51, 51, 51]
	// bits, like the ones returned by lightReduce.
	const maskLow52Bits = (1 << 52) - 1
	return fieldElement{
		rand.Uint64() & maskLow52Bits,
		rand.Uint64() & maskLow51Bits,
		rand.Uint64() & maskLow51Bits,
		rand.Uint64() & maskLow51Bits,
		rand.Uint64() & maskLow51Bits,
	}
}

// weirdLimbs can be combined to generate a range of edge-case field elements.
// 0 and -1 are intentionally more weighted, as they combine well.
var (
	weirdLimbs51 = []uint64{
		0, 0, 0, 0,
		1,
		19 - 1,
		19,
		0x2aaaaaaaaaaaa,
		0x5555555555555,
		(1 << 51) - 20,
		(1 << 51) - 19,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
	}
	weirdLimbs52 = []uint64{
		0, 0, 0, 0, 0, 0,
		1,
		19 - 1,
		19,
		0x2aaaaaaaaaaaa,
		0x5555555555555,
		(1 << 51) - 20,
		(1 << 51) - 19,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
		(1 << 51) - 1, (1 << 51) - 1,
		1 << 51,
		(1 << 51) + 1,
		(1 << 52) - 19,
		(1 << 52) - 1,
	}
)

func generateWeirdFieldElement(rand *mathrand.Rand) fieldElement {
	return fieldElement{
		weirdLimbs52[rand.Intn(len(weirdLimbs52))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
	}
}

func (fieldElement) Generate(rand *mathrand.Rand, size int) reflect.Value {
	if rand.Intn(2) == 0 {
		return reflect.ValueOf(generateWeirdFieldElement(rand))
	}
	return reflect.ValueOf(generateFieldElement(rand))
}

// isInBounds returns whether the element is within the expected bit size bounds
// after a light reduction.
func isInBounds(x *fieldElement) bool {
	return bits.Len64(x.l0) <= 52 &&
		bits.Len64(x.l1) <= 52 &&
		bits.Len64(x.l2) <= 52 &&
		bits.Len64(x.l3) <= 52 &&
		bits.Len64(x.l4) <= 52
}

func TestMulDistributesOverAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z fieldElement) bool {
		// Compute t1 = (x+y)*z
		t1 := new(fieldElement)
		t1.Add(&x, &y)
		t1.Multiply(t1, &z)

		// Compute t2 = x*z + y*z
		t2 := new(fieldElement)
		t3 := new(fieldElement)
		t2.Multiply(&x, &z)
		t3.Multiply(&y, &z)
		t2.Add(t2, t3)

		return t1.Equal(t2) == 1 && isInBounds(t1) && isInBounds(t2)
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig1024); err != nil {
		t.Error(err)
	}
}

func TestMul64to128(t *testing.T) {
	a := uint64(5)
	b := uint64(5)
	r0, r1 := madd64(0, 0, a, b)
	if r0 != 0x19 || r1 != 0 {
		t.Errorf("lo-range wide mult failed, got %d + %d*(2**64)", r0, r1)
	}

	a = uint64(18014398509481983) // 2^54 - 1
	b = uint64(18014398509481983) // 2^54 - 1
	r0, r1 = madd64(0, 0, a, b)
	if r0 != 0xff80000000000001 || r1 != 0xfffffffffff {
		t.Errorf("hi-range wide mult failed, got %d + %d*(2**64)", r0, r1)
	}

	a = uint64(1125899906842661)
	b = uint64(2097155)
	r0, r1 = madd64(0, 0, a, b)
	r0, r1 = madd64(r0, r1, a, b)
	r0, r1 = madd64(r0, r1, a, b)
	r0, r1 = madd64(r0, r1, a, b)
	r0, r1 = madd64(r0, r1, a, b)
	if r0 != 16888498990613035 || r1 != 640 {
		t.Errorf("wrong answer: %d + %d*(2**64)", r0, r1)
	}
}

var r0, r1 uint64

func BenchmarkWideMultCall(t *testing.B) {
	a := uint64(18014398509481983)
	b := uint64(18014398509481983)

	for i := 0; i < t.N; i++ {
		r0, r1 = madd64(r0, r1, a, b)
	}
}

func TestSetBytesRoundTrip(t *testing.T) {
	f1 := func(in [32]byte, fe fieldElement) bool {
		fe.SetBytes(in[:])

		// Mask the most significant bit as it's ignored by SetBytes. (Now
		// instead of earlier so we check the masking in SetBytes is working.)
		in[len(in)-1] &= (1 << 7) - 1

		// TODO: values in the range [2^255-19, 2^255-1] will still fail the
		// comparison as they will have been reduced in the round-trip, but the
		// current quickcheck generation strategy will never hit them, which is
		// not good. We should have a weird generator that aims for edge cases,
		// and we'll know it works when this test breaks.

		return bytes.Equal(in[:], fe.Bytes()) && isInBounds(&fe)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Errorf("failed bytes->FE->bytes round-trip: %v", err)
	}

	f2 := func(fe, r fieldElement) bool {
		r.SetBytes(fe.Bytes())

		// Intentionally not using Equal not to go through Bytes again.
		// Calling reduce because both Generate and SetBytes can produce
		// non-canonical representations.
		fe.reduce()
		r.reduce()
		return fe == r
	}
	if err := quick.Check(f2, nil); err != nil {
		t.Errorf("failed FE->bytes->FE round-trip: %v", err)
	}

	// Check some fixed vectors from dalek
	type feRTTest struct {
		fe fieldElement
		b  []byte
	}
	var tests = []feRTTest{
		{
			fe: fieldElement{358744748052810, 1691584618240980, 977650209285361, 1429865912637724, 560044844278676},
			b:  []byte{74, 209, 69, 197, 70, 70, 161, 222, 56, 226, 229, 19, 112, 60, 25, 92, 187, 74, 222, 56, 50, 153, 51, 233, 40, 74, 57, 6, 160, 185, 213, 31},
		},
		{
			fe: fieldElement{84926274344903, 473620666599931, 365590438845504, 1028470286882429, 2146499180330972},
			b:  []byte{199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122},
		},
	}

	for _, tt := range tests {
		b := tt.fe.Bytes()
		if !bytes.Equal(b, tt.b) || new(fieldElement).SetBytes(tt.b).Equal(&tt.fe) != 1 {
			t.Errorf("Failed fixed roundtrip: %v", tt)
		}
	}
}

func swapEndianness(buf []byte) []byte {
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[len(buf)-i-1] = buf[len(buf)-i-1], buf[i]
	}
	return buf
}

func TestBytesBigEquivalence(t *testing.T) {
	f1 := func(in [32]byte, fe, fe1 fieldElement) bool {
		fe.SetBytes(in[:])

		in[len(in)-1] &= (1 << 7) - 1 // mask the most significant bit
		b := new(big.Int).SetBytes(swapEndianness(in[:]))
		fe1.fromBig(b)

		if fe != fe1 {
			return false
		}

		buf := make([]byte, 32) // pad with zeroes
		copy(buf, swapEndianness(fe1.toBig().Bytes()))

		return bytes.Equal(fe.Bytes(), buf) && isInBounds(&fe) && isInBounds(&fe1)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Error(err)
	}
}

// fromBig sets v = n, and returns v. The bit length of n must not exceed 256.
func (v *fieldElement) fromBig(n *big.Int) *fieldElement {
	if n.BitLen() > 32*8 {
		panic("edwards25519: invalid field element input size")
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

	return v.SetBytes(buf[:32])
}

func (v *fieldElement) fromDecimal(s string) *fieldElement {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("not a valid decimal: " + s)
	}
	return v.fromBig(n)
}

// toBig returns v as a big.Int.
func (v *fieldElement) toBig() *big.Int {
	buf := v.Bytes()

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

func TestDecimalConstants(t *testing.T) {
	sqrtM1String := "19681161376707505956807079304988542015446066515923890162744021073123829784752"
	if exp := (&fieldElement{}).fromDecimal(sqrtM1String); sqrtM1.Equal(exp) != 1 {
		t.Errorf("sqrtM1 is %v, expected %v", sqrtM1, exp)
	}
	dString := "37095705934669439343138083508754565189542113879843219016388785533085940283555"
	if exp := (&fieldElement{}).fromDecimal(dString); d.Equal(exp) != 1 {
		t.Errorf("d is %v, expected %v", d, exp)
	}
}

func TestSetBytesRoundTripEdgeCases(t *testing.T) {
	// TODO: values close to 0, close to 2^255-19, between 2^255-19 and 2^255-1,
	// and between 2^255 and 2^256-1. Test both the documented SetBytes
	// behavior, and that Bytes reduces them.
}

// Tests self-consistency between FeMul and FeSquare.
func TestSanity(t *testing.T) {
	var x fieldElement
	var x2, x2sq fieldElement
	// var x2Go, x2sqGo fieldElement

	x = fieldElement{1, 1, 1, 1, 1}
	x2.Multiply(&x, &x)
	// FeMulGo(&x2Go, &x, &x)
	x2sq.Square(&x)
	// FeSquareGo(&x2sqGo, &x)

	// if !vartimeEqual(x2, x2Go) || !vartimeEqual(x2sq, x2sqGo) || !vartimeEqual(x2, x2sq) {
	// 	t.Fatalf("all ones failed\nmul.s: %d\nmul.g: %d\nsqr.s: %d\nsqr.g: %d\n", x2, x2Go, x2sq, x2sqGo)
	// }

	if x2 != x2sq {
		t.Fatalf("all ones failed\nmul: %x\nsqr: %x\n", x2, x2sq)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	x.SetBytes(bytes[:])

	x2.Multiply(&x, &x)
	// FeMulGo(&x2Go, &x, &x)
	x2sq.Square(&x)
	// FeSquareGo(&x2sqGo, &x)

	// if !vartimeEqual(x2, x2Go) || !vartimeEqual(x2sq, x2sqGo) || !vartimeEqual(x2, x2sq) {
	// 	t.Fatalf("random field element failed\nfe: %x\n\nmul.s: %x\nmul.g: %x\nsqr.s: %x\nsqr.g: %x\n", x, x2, x2Go, x2sq, x2sqGo)
	// }

	if x2 != x2sq {
		t.Fatalf("all ones failed\nmul: %x\nsqr: %x\n", x2, x2sq)
	}
}

func TestEqual(t *testing.T) {
	x := fieldElement{1, 1, 1, 1, 1}
	y := fieldElement{5, 4, 3, 2, 1}

	eq := x.Equal(&x)
	if eq != 1 {
		t.Errorf("wrong about equality")
	}

	eq = x.Equal(&y)
	if eq != 0 {
		t.Errorf("wrong about inequality")
	}
}

func TestInvert(t *testing.T) {
	x := fieldElement{1, 1, 1, 1, 1}
	one := fieldElement{1, 0, 0, 0, 0}
	var xinv, r fieldElement

	xinv.Invert(&x)
	r.Multiply(&x, &xinv)
	r.reduce()

	if one != r {
		t.Errorf("inversion identity failed, got: %x", r)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	x.SetBytes(bytes[:])

	xinv.Invert(&x)
	r.Multiply(&x, &xinv)
	r.reduce()

	if one != r {
		t.Errorf("random inversion identity failed, got: %x for field element %x", r, x)
	}

	zero := fieldElement{}
	x.Set(&zero)
	if xx := xinv.Invert(&x); xx != &xinv {
		t.Errorf("inverting zero did not return the receiver")
	} else if xinv.Equal(&zero) != 1 {
		t.Errorf("inverting zero did not return zero")
	}
}

func TestSelectSwap(t *testing.T) {
	a := fieldElement{358744748052810, 1691584618240980, 977650209285361, 1429865912637724, 560044844278676}
	b := fieldElement{84926274344903, 473620666599931, 365590438845504, 1028470286882429, 2146499180330972}

	var c, d fieldElement

	c.Select(&a, &b, 1)
	d.Select(&a, &b, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Select failed")
	}

	c.Swap(&d, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Swap failed")
	}

	c.Swap(&d, 1)

	if c.Equal(&b) != 1 || d.Equal(&a) != 1 {
		t.Errorf("Swap failed")
	}
}

func TestMul32(t *testing.T) {
	mul32EquivalentToMul := func(x fieldElement, y uint32) bool {
		t1 := new(fieldElement)
		for i := 0; i < 100; i++ {
			t1.Mult32(&x, y)
		}

		ty := new(fieldElement)
		ty.l0 = uint64(y)

		t2 := new(fieldElement)
		for i := 0; i < 100; i++ {
			t2.Multiply(&x, ty)
		}

		return t1.Equal(t2) == 1 && isInBounds(t1) && isInBounds(t2)
	}

	if err := quick.Check(mul32EquivalentToMul, quickCheckConfig1024); err != nil {
		t.Error(err)
	}
}

func TestSqrtRatio(t *testing.T) {
	// From draft-irtf-cfrg-ristretto255-decaf448-00, Appendix A.4.
	type test struct {
		u, v      string
		wasSquare int
		r         string
	}
	var tests = []test{
		// If u is 0, the function is defined to return (0, TRUE), even if v
		// is zero. Note that where used in this package, the denominator v
		// is never zero.
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000000",
			1, "0000000000000000000000000000000000000000000000000000000000000000",
		},
		// 0/1 == 0²
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000000",
			1, "0000000000000000000000000000000000000000000000000000000000000000",
		},
		// If u is non-zero and v is zero, defined to return (0, FALSE).
		{
			"0100000000000000000000000000000000000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000000",
			0, "0000000000000000000000000000000000000000000000000000000000000000",
		},
		// 2/1 is not square in this field.
		{
			"0200000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000000",
			0, "3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54",
		},
		// 4/1 == 2²
		{
			"0400000000000000000000000000000000000000000000000000000000000000",
			"0100000000000000000000000000000000000000000000000000000000000000",
			1, "0200000000000000000000000000000000000000000000000000000000000000",
		},
		// 1/4 == (2⁻¹)² == (2^(p-2))² per Euler's theorem
		{
			"0100000000000000000000000000000000000000000000000000000000000000",
			"0400000000000000000000000000000000000000000000000000000000000000",
			1, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
		},
	}

	for i, tt := range tests {
		u := (&fieldElement{}).SetBytes(decodeHex(tt.u))
		v := (&fieldElement{}).SetBytes(decodeHex(tt.v))
		want := (&fieldElement{}).SetBytes(decodeHex(tt.r))
		got, wasSquare := (&fieldElement{}).SqrtRatio(u, v)
		if got.Equal(want) == 0 || wasSquare != tt.wasSquare {
			t.Errorf("%d: got (%v, %v), want (%v, %v)", i, got, wasSquare, want, tt.wasSquare)
		}
	}
}

func TestCarryPropagate(t *testing.T) {
	asmLikeGeneric := func(a [5]uint64) bool {
		t1 := &fieldElement{a[0], a[1], a[2], a[3], a[4]}
		t2 := &fieldElement{a[0], a[1], a[2], a[3], a[4]}

		t1.carryPropagate()
		t2.carryPropagateGeneric()

		if *t1 != *t2 {
			t.Logf("got: %#v,\nexpected: %#v", t1, t2)
		}

		return *t1 == *t2 && isInBounds(t2)
	}

	if err := quick.Check(asmLikeGeneric, quickCheckConfig1024); err != nil {
		t.Error(err)
	}

	if !asmLikeGeneric([5]uint64{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}) {
		t.Errorf("failed for {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}")
	}
}
