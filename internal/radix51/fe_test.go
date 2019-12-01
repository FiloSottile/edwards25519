// Copyright (c) 2017 George Tankersley. All rights reserved.
// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix51

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"math/bits"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// quickCheckConfig will make each quickcheck test run (1024 * -quickchecks)
// times. The default value of -quickchecks is 100.
var quickCheckConfig = &quick.Config{MaxCountScale: 1 << 10}

func generateFieldElement(rand *mathrand.Rand) FieldElement {
	// Generation strategy: generate random limb values of [52, 51, 51, 51, 51]
	// bits, like the ones returned by lightReduce.
	const maskLow52Bits = (1 << 52) - 1
	return FieldElement{
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

func generateWeirdFieldElement(rand *mathrand.Rand) FieldElement {
	return FieldElement{
		weirdLimbs52[rand.Intn(len(weirdLimbs52))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
		weirdLimbs51[rand.Intn(len(weirdLimbs51))],
	}
}

func (x FieldElement) Generate(rand *mathrand.Rand, size int) reflect.Value {
	if rand.Intn(2) == 0 {
		return reflect.ValueOf(generateWeirdFieldElement(rand))
	}
	return reflect.ValueOf(generateFieldElement(rand))
}

// isInBounds returns whether the element is within the expected bit size bounds
// after a light reduction.
func isInBounds(x *FieldElement) bool {
	return bits.Len64(x[0]) <= 52 &&
		bits.Len64(x[1]) <= 51 &&
		bits.Len64(x[2]) <= 51 &&
		bits.Len64(x[3]) <= 51 &&
		bits.Len64(x[4]) <= 51
}

func TestMulDistributesOverAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z FieldElement) bool {
		// Compute t1 = (x+y)*z
		t1 := new(FieldElement)
		t1.Add(&x, &y)
		t1.Mul(t1, &z)

		// Compute t2 = x*z + y*z
		t2 := new(FieldElement)
		t3 := new(FieldElement)
		t2.Mul(&x, &z)
		t3.Mul(&y, &z)
		t2.Add(t2, t3)

		return t1.Equal(t2) == 1 && isInBounds(t1) && isInBounds(t2)
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
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

func TestFromBytesRoundTrip(t *testing.T) {
	f1 := func(in, out [32]byte, fe FieldElement) bool {
		fe.FromBytes(in[:])
		fe.Bytes(out[:0])

		// Mask the most significant bit as it's ignored by FromBytes. (Now
		// instead of earlier so we check the masking in FromBytes is working.)
		in[len(in)-1] &= (1 << 7) - 1

		// TODO: values in the range [2^255-19, 2^255-1] will still fail the
		// comparison as they will have been reduced in the round-trip, but the
		// current quickcheck generation strategy will never hit them, which is
		// not good. We should have a weird generator that aims for edge cases,
		// and we'll know it works when this test breaks.

		return bytes.Equal(in[:], out[:]) && isInBounds(&fe)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Errorf("failed bytes->FE->bytes round-trip: %v", err)
	}

	f2 := func(fe, r FieldElement, out [32]byte) bool {
		fe.Bytes(out[:0])
		r.FromBytes(out[:])

		// Intentionally not using Equal not to go through Bytes again.
		// Calling reduce because both Generate and FromBytes can produce
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
		fe FieldElement
		b  []byte
	}
	var tests = []feRTTest{
		{
			fe: FieldElement([5]uint64{358744748052810, 1691584618240980, 977650209285361, 1429865912637724, 560044844278676}),
			b:  []byte{74, 209, 69, 197, 70, 70, 161, 222, 56, 226, 229, 19, 112, 60, 25, 92, 187, 74, 222, 56, 50, 153, 51, 233, 40, 74, 57, 6, 160, 185, 213, 31},
		},
		{
			fe: FieldElement([5]uint64{84926274344903, 473620666599931, 365590438845504, 1028470286882429, 2146499180330972}),
			b:  []byte{199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122},
		},
	}

	for _, tt := range tests {
		if !bytes.Equal(tt.fe.Bytes(nil), tt.b) || new(FieldElement).FromBytes(tt.b).Equal(&tt.fe) != 1 {
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
	f1 := func(in, out [32]byte, fe, fe1 FieldElement) bool {
		fe.FromBytes(in[:])

		in[len(in)-1] &= (1 << 7) - 1 // mask the most significant bit
		b := new(big.Int).SetBytes(swapEndianness(in[:]))
		fe1.FromBig(b)

		if fe != fe1 {
			return false
		}

		fe.Bytes(out[:0])
		buf := make([]byte, 32) // pad with zeroes
		copy(buf, swapEndianness(fe1.ToBig().Bytes()))

		return bytes.Equal(out[:], buf) && isInBounds(&fe) && isInBounds(&fe1)
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Error(err)
	}
}

func TestFromBytesRoundTripEdgeCases(t *testing.T) {
	// TODO: values close to 0, close to 2^255-19, between 2^255-19 and 2^255-1,
	// and between 2^255 and 2^256-1. Test both the documented FromBytes
	// behavior, and that Bytes reduces them.
}

// Tests self-consistency between FeMul and FeSquare.
func TestSanity(t *testing.T) {
	var x FieldElement
	var x2, x2sq FieldElement
	// var x2Go, x2sqGo FieldElement

	x = [5]uint64{1, 1, 1, 1, 1}
	x2.Mul(&x, &x)
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
	x.FromBytes(bytes[:])

	x2.Mul(&x, &x)
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
	var x FieldElement = [5]uint64{1, 1, 1, 1, 1}
	var y FieldElement = [5]uint64{5, 4, 3, 2, 1}

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
	var x FieldElement = [5]uint64{1, 1, 1, 1, 1}
	var one FieldElement = [5]uint64{1, 0, 0, 0, 0}
	var xinv, r FieldElement

	xinv.Invert(&x)
	r.Mul(&x, &xinv)
	r.reduce()

	if one != r {
		t.Errorf("inversion identity failed, got: %x", r)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	x.FromBytes(bytes[:])

	xinv.Invert(&x)
	r.Mul(&x, &xinv)
	r.reduce()

	if one != r {
		t.Errorf("random inversion identity failed, got: %x for field element %x", r, x)
	}
}

func TestSelectSwap(t *testing.T) {
	a := FieldElement([5]uint64{358744748052810, 1691584618240980, 977650209285361, 1429865912637724, 560044844278676})
	b := FieldElement([5]uint64{84926274344903, 473620666599931, 365590438845504, 1028470286882429, 2146499180330972})

	var c, d FieldElement

	c.Select(&a, &b, 1)
	d.Select(&a, &b, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Select failed")
	}

	CondSwap(&c, &d, 0)

	if c.Equal(&a) != 1 || d.Equal(&b) != 1 {
		t.Errorf("Swap failed")
	}

	CondSwap(&c, &d, 1)

	if c.Equal(&b) != 1 || d.Equal(&a) != 1 {
		t.Errorf("Swap failed")
	}
}

func TestMul32(t *testing.T) {
	isAlmostInBounds := func(x *FieldElement) bool {
		return bits.Len64(x[0]) <= 52 &&
			bits.Len64(x[1]) <= 52 &&
			bits.Len64(x[2]) <= 52 &&
			bits.Len64(x[3]) <= 52 &&
			bits.Len64(x[4]) <= 52
	}

	mul32EquivalentToMul := func(x FieldElement, y uint32) bool {
		t1 := new(FieldElement)
		for i := 0; i < 100; i++ {
			t1.Mul32(&x, y)
		}

		ty := new(FieldElement)
		ty[0] = uint64(y)

		t2 := new(FieldElement)
		for i := 0; i < 100; i++ {
			t2.Mul(&x, ty)
		}

		return t1.Equal(t2) == 1 && isAlmostInBounds(t1) && isInBounds(t2)
	}

	if err := quick.Check(mul32EquivalentToMul, quickCheckConfig); err != nil {
		t.Error(err)
	}
}
