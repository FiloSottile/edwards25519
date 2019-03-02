// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix51

import (
	"bytes"
	"crypto/rand"
	"io"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

var quickCheckScaleFactor = uint8(3)
var quickCheckConfig = &quick.Config{MaxCount: (1 << (12 + quickCheckScaleFactor))}

func generateFieldElement(rand *mathrand.Rand) FieldElement {
	// Generation strategy: generate random limb values bounded by
	// 2**(51+b), where b is a parameter controlling the bit-excess.
	b := uint64(0)
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

func TestFeFromBytesRoundTrip(t *testing.T) {
	var in, out [32]byte
	var fe, r FieldElement

	in = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
		18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	fe.FromBytes(&in)
	fe.ToBytes(&out)

	if !bytes.Equal(in[:], out[:]) {
		t.Error("Bytes<>FE doesn't roundtrip")
	}

	// Random field element
	fe[0] = 0x4e645be9215a2
	fe[1] = 0x4e9654922df12
	fe[2] = 0x5829e468b0205
	fe[3] = 0x5e8fca9e0881c
	fe[4] = 0x5c490f087d796

	fe.ToBytes(&out)
	r.FromBytes(&out)

	for i := 0; i < len(fe); i++ {
		if r[i] != fe[i] {
			t.Error("FE<>Bytes doesn't roundtrip")
		}
	}
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
	x.FromBytes(&bytes)

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
	r.Reduce(&r)

	if !vartimeEqual(one, r) {
		t.Errorf("inversion identity failed, got: %x", r)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	x.FromBytes(&bytes)

	xinv.Invert(&x)
	r.Mul(&x, &xinv)
	r.Reduce(&r)

	if !vartimeEqual(one, r) {
		t.Errorf("random inversion identity failed, got: %x for field element %x", r, x)
	}
}
