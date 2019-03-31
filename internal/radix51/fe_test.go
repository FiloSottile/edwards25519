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
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// quickCheckConfig will make each quickcheck test run (256 * -quickchecks)
// times. The default value of -quickchecks is 100.
var quickCheckConfig = &quick.Config{MaxCountScale: 1 << 8}

func generateFieldElement(rand *mathrand.Rand) FieldElement {
	// Generation strategy: generate random limb values bounded by
	// 2**(51+b), where b is a parameter controlling the bit-excess.
	// TODO: randomly decide to set the limbs to "weird" values.
	b := uint64(0) // TODO: set this higher once we know the bounds.
	mask := (uint64(1) << (51 + b)) - 1
	return FieldElement{
		rand.Uint64() & mask,
		rand.Uint64() & mask,
		rand.Uint64() & mask,
		rand.Uint64() & mask,
		rand.Uint64() & mask,
	}
}

func (x FieldElement) Generate(rand *mathrand.Rand, size int) reflect.Value {
	return reflect.ValueOf(generateFieldElement(rand))
}

func TestFieldElementMulDistributesOverAdd(t *testing.T) {
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

		return t1.Equal(t2) == 1
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}

func TestMulDistributionFailure1(t *testing.T) {
	x := FieldElement{0x592101fd8643a, 0x25a08467381e1, 0x48cb4dcd5dcf5, 0x1074d52744164, 0x91902aac541b}
	y := FieldElement{0x165bb67340a7f, 0x52cf7781f4ad6, 0x32534ba21fde4, 0x5b4ba9cbb1736, 0x2e90748c54289}
	z := FieldElement{0x25a575665ad1e, 0x124e496e3eeaa, 0x433d2180e2561, 0x221c8be3aa11a, 0x7adc8d0adf806}

	t1 := new(FieldElement)
	t1.Add(&x, &y)
	t1.Mul(t1, &z)

	// Compute t2 = x*z + y*z
	t2 := new(FieldElement)
	t3 := new(FieldElement)
	t2.Mul(&x, &z)
	t3.Mul(&y, &z)
	t2.Add(t2, t3)

	if t1.Equal(t2) != 1 {
		t.Errorf("t1 = %x should equal t2 = %x", t1, t2)
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

func BenchmarkWideMultCall(t *testing.B) {
	var r0, r1 uint64
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

		return bytes.Equal(in[:], out[:])
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
		fe.reduce(&fe)
		r.reduce(&r)
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

		return bytes.Equal(out[:], buf)
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

	if !vartimeEqual(x2, x2sq) {
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

	if !vartimeEqual(x2, x2sq) {
		t.Fatalf("all ones failed\nmul: %x\nsqr: %x\n", x2, x2sq)
	}
}

func vartimeEqual(x, y FieldElement) bool {
	for i := 0; i < 5; i++ {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func TestFeEqual(t *testing.T) {
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

func TestFeInvert(t *testing.T) {
	var x FieldElement = [5]uint64{1, 1, 1, 1, 1}
	var one FieldElement = [5]uint64{1, 0, 0, 0, 0}
	var xinv, r FieldElement

	xinv.Invert(&x)
	r.Mul(&x, &xinv)
	r.reduce(&r)

	if !vartimeEqual(one, r) {
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
	r.reduce(&r)

	if !vartimeEqual(one, r) {
		t.Errorf("random inversion identity failed, got: %x for field element %x", r, x)
	}
}
