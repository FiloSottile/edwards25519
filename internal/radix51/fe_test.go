// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix51

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"unsafe"
)

func TestMul64to128(t *testing.T) {
	a := uint64(5)
	b := uint64(5)
	r0, r1 := mul64x64(0, 0, a, b)
	if r0 != 0x19 || r1 != 0 {
		t.Errorf("lo-range wide mult failed, got %d + %d*(2**64)", r0, r1)
	}

	a = uint64(18014398509481983) // 2^54 - 1
	b = uint64(18014398509481983) // 2^54 - 1
	r0, r1 = mul64x64(0, 0, a, b)
	if r0 != 0xff80000000000001 || r1 != 0xfffffffffff {
		t.Errorf("hi-range wide mult failed, got %d + %d*(2**64)", r0, r1)
	}

	a = uint64(1125899906842661)
	b = uint64(2097155)
	r0, r1 = mul64x64(0, 0, a, b)
	r0, r1 = mul64x64(r0, r1, a, b)
	r0, r1 = mul64x64(r0, r1, a, b)
	r0, r1 = mul64x64(r0, r1, a, b)
	r0, r1 = mul64x64(r0, r1, a, b)
	if r0 != 16888498990613035 || r1 != 640 {
		t.Errorf("wrong answer: %d + %d*(2**64)", r0, r1)
	}
}

func BenchmarkWideMultInline(t *testing.B) {
	var r0, r1, ol, oh uint64
	a := uint64(18014398509481983) // 2^54 - 1
	b := uint64(18014398509481983) // 2^54 - 1

	for i := 0; i < t.N; i++ {
		t1 := (a>>32)*(b&0xFFFFFFFF) + ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF) >> 32)
		t2 := (a&0xFFFFFFFF)*(b>>32) + (t1 & 0xFFFFFFFF)
		ol = (a * b) + r0
		cmp := ol < r0
		oh = r1 + (a>>32)*(b>>32) + t1>>32 + t2>>32 + uint64(*(*byte)(unsafe.Pointer(&cmp)))

		r1 = oh
		r0 = ol
	}
}

func BenchmarkWideMultCall(t *testing.B) {
	var r0, r1 uint64
	a := uint64(18014398509481983)
	b := uint64(18014398509481983)

	for i := 0; i < t.N; i++ {
		r0, r1 = mul64x64(r0, r1, a, b)
	}
}

func TestFeFromBytesRoundTrip(t *testing.T) {
	var in, out [32]byte
	var fe, r FieldElement

	in = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
		18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	FeFromBytes(&fe, &in)
	FeToBytes(&out, &fe)

	if !bytes.Equal(in[:], out[:]) {
		t.Error("Bytes<>FE doesn't roundtrip")
	}

	// Random field element
	fe[0] = 0x4e645be9215a2
	fe[1] = 0x4e9654922df12
	fe[2] = 0x5829e468b0205
	fe[3] = 0x5e8fca9e0881c
	fe[4] = 0x5c490f087d796

	FeToBytes(&out, &fe)
	FeFromBytes(&r, &out)

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
	FeMul(&x2, &x, &x)
	// FeMulGo(&x2Go, &x, &x)
	FeSquare(&x2sq, &x)
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
	FeFromBytes(&x, &bytes)

	FeMul(&x2, &x, &x)
	// FeMulGo(&x2Go, &x, &x)
	FeSquare(&x2sq, &x)
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

	eq := FeEqual(&x, &x)
	if !eq {
		t.Errorf("wrong about equality")
	}

	eq = FeEqual(&x, &y)
	if eq {
		t.Errorf("wrong about inequality")
	}
}

func TestFeInvert(t *testing.T) {
	var x FieldElement = [5]uint64{1, 1, 1, 1, 1}
	var one FieldElement = [5]uint64{1, 0, 0, 0, 0}
	var xinv, r FieldElement

	FeInvert(&xinv, &x)
	FeMul(&r, &x, &xinv)
	FeReduce(&r, &r)

	if !vartimeEqual(one, r) {
		t.Errorf("inversion identity failed, got: %x", r)
	}

	var bytes [32]byte

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	FeFromBytes(&x, &bytes)

	FeInvert(&xinv, &x)
	FeMul(&r, &x, &xinv)
	FeReduce(&r, &r)

	if !vartimeEqual(one, r) {
		t.Errorf("random inversion identity failed, got: %x for field element %x", r, x)
	}
}
