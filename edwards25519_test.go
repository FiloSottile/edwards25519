// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"encoding/hex"
	"reflect"
	"testing"
	"testing/quick"
)

var B = NewGeneratorPoint()
var I = NewIdentityPoint()

func checkOnCurve(t *testing.T, points ...*Point) {
	t.Helper()
	for i, p := range points {
		var XX, YY, ZZ, ZZZZ fieldElement
		XX.Square(&p.x)
		YY.Square(&p.y)
		ZZ.Square(&p.z)
		ZZZZ.Square(&ZZ)
		// -x² + y² = 1 + dx²y²
		// -(X/Z)² + (Y/Z)² = 1 + d(X/Z)²(Y/Z)²
		// (-X² + Y²)/Z² = 1 + (dX²Y²)/Z⁴
		// (-X² + Y²)*Z² = Z⁴ + dX²Y²
		var lhs, rhs fieldElement
		lhs.Subtract(&YY, &XX).Multiply(&lhs, &ZZ)
		rhs.Multiply(d, &XX).Multiply(&rhs, &YY).Add(&rhs, &ZZZZ)
		if lhs.Equal(&rhs) != 1 {
			t.Errorf("X, Y, and Z do not specify a point on the curve\nX = %v\nY = %v\nZ = %v", p.x, p.y, p.z)
		}
		// xy = T/Z
		lhs.Multiply(&p.x, &p.y)
		rhs.Multiply(&p.z, &p.t)
		if lhs.Equal(&rhs) != 1 {
			t.Errorf("point %d is not valid\nX = %v\nY = %v\nZ = %v", i, p.x, p.y, p.z)
		}
	}
}

func TestAddSubNegOnBasePoint(t *testing.T) {
	Bneg := &Point{}
	tmpP2 := &projP2{}
	tmpP1xP1 := &projP1xP1{}
	tmpCached := &projCached{}

	Bneg.Negate(B)

	checkLhs, checkRhs := &Point{}, &Point{}

	tmpCached.FromP3(B)
	tmpP1xP1.Add(B, tmpCached)
	checkLhs.fromP1xP1(tmpP1xP1)
	tmpP2.FromP3(B)
	tmpP1xP1.Double(tmpP2)
	checkRhs.fromP1xP1(tmpP1xP1)
	if checkLhs.Equal(checkRhs) != 1 {
		t.Error("B + B != [2]B")
	}

	tmpCached.FromP3(B)
	tmpP1xP1.Sub(B, tmpCached)
	checkLhs.fromP1xP1(tmpP1xP1)
	tmpCached.FromP3(Bneg)
	tmpP1xP1.Add(B, tmpCached)
	checkRhs.fromP1xP1(tmpP1xP1)
	if checkLhs.Equal(checkRhs) != 1 {
		t.Error("B - B != B + (-B)")
	}
	if I.Equal(checkLhs) != 1 {
		t.Error("B - B != 0")
	}
	if I.Equal(checkRhs) != 1 {
		t.Error("B + (-B) != 0")
	}
	checkOnCurve(t, checkLhs, checkRhs, Bneg)
}

func TestComparable(t *testing.T) {
	if reflect.TypeOf(Point{}).Comparable() {
		t.Error("Point is unexpectedly comparable")
	}
}

func TestInvalidEncodings(t *testing.T) {
	// An invalid point, that also happens to have y > p.
	invalid := "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	p := NewGeneratorPoint()
	if out, err := p.SetBytes(decodeHex(invalid)); err == nil {
		t.Error("expected error for invalid point")
	} else if out != nil {
		t.Error("SetBytes did not return nil on an invalid encoding")
	} else if p.Equal(B) != 1 {
		t.Error("the Point was modified while decoding an invalid encoding")
	}
	checkOnCurve(t, p)
}

func TestNonCanonicalPoints(t *testing.T) {
	type test struct {
		name                string
		encoding, canonical string
	}
	tests := []test{
		// Points with x = 0 and the sign bit set. With x = 0 the curve equation
		// gives y² = 1, so y = ±1. 1 has two valid encodings.
		{
			"y=1,sign-",
			"0100000000000000000000000000000000000000000000000000000000000080",
			"0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+1,sign-",
			"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0100000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p-1,sign-",
			"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		},

		// Non-canonical y encodings with values 2²⁵⁵-19 (p) to 2²⁵⁵-1 (p+18).
		{
			"y=p,sign+",
			"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p,sign-",
			"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0000000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+1,sign+",
			"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0100000000000000000000000000000000000000000000000000000000000000",
		},
		// "y=p+1,sign-" is already tested above.
		// p+2 is not a valid y-coordinate.
		{
			"y=p+3,sign+",
			"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0300000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+3,sign-",
			"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0300000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+4,sign+",
			"f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0400000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+4,sign-",
			"f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0400000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+5,sign+",
			"f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0500000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+5,sign-",
			"f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0500000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+6,sign+",
			"f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0600000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+6,sign-",
			"f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0600000000000000000000000000000000000000000000000000000000000080",
		},
		// p+7 is not a valid y-coordinate.
		// p+8 is not a valid y-coordinate.
		{
			"y=p+9,sign+",
			"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0900000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+9,sign-",
			"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0900000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+10,sign+",
			"f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0a00000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+10,sign-",
			"f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0a00000000000000000000000000000000000000000000000000000000000080",
		},
		// p+11 is not a valid y-coordinate.
		// p+12 is not a valid y-coordinate.
		// p+13 is not a valid y-coordinate.
		{
			"y=p+14,sign+",
			"fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0e00000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+14,sign-",
			"fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0e00000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+15,sign+",
			"fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"0f00000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+15,sign-",
			"fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"0f00000000000000000000000000000000000000000000000000000000000080",
		},
		{
			"y=p+16,sign+",
			"fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"1000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+16,sign-",
			"fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"1000000000000000000000000000000000000000000000000000000000000080",
		},
		// p+17 is not a valid y-coordinate.
		{
			"y=p+18,sign+",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
			"1200000000000000000000000000000000000000000000000000000000000000",
		},
		{
			"y=p+18,sign-",
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			"1200000000000000000000000000000000000000000000000000000000000080",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, err := (&Point{}).SetBytes(decodeHex(tt.encoding))
			if err != nil {
				t.Fatalf("error decoding non-canonical point: %v", err)
			}
			p2, err := (&Point{}).SetBytes(decodeHex(tt.canonical))
			if err != nil {
				t.Fatalf("error decoding canonical point: %v", err)
			}
			if p1.Equal(p2) != 1 {
				t.Errorf("equivalent points are not equal: %v, %v", p1, p2)
			}
			if encoding := hex.EncodeToString(p1.Bytes()); encoding != tt.canonical {
				t.Errorf("re-encoding does not match canonical; got %q, expected %q", encoding, tt.canonical)
			}
			checkOnCurve(t, p1, p2)
		})
	}
}

// TestBytesMontgomery tests the SetBytesWithClamping+BytesMontgomery path
// equivalence to X25519. (Note that you intentionally can't actually implement
// full X25519 with this package because there is no SetBytesMontgomery.)
// Disabled to avoid the golang.org/x/crypto module dependency.
/* func TestBytesMontgomery(t *testing.T) {
	f := func(scalar [32]byte) bool {
		s := NewScalar().SetBytesWithClamping(scalar[:])
		p := (&Point{}).ScalarBaseMult(s)
		got := p.BytesMontgomery()
		want, _ := curve25519.X25519(scalar[:], curve25519.Basepoint)
		return bytes.Equal(got, want)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
} */

func TestBytesMontgomerySodium(t *testing.T) {
	// Generated with libsodium.js 1.0.18
	// crypto_sign_keypair().publicKey
	publicKey := "3bf918ffc2c955dc895bf145f566fb96623c1cadbe040091175764b5fde322c0"
	p, err := (&Point{}).SetBytes(decodeHex(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	// crypto_sign_ed25519_pk_to_curve25519(publicKey)
	want := "efc6c9d0738e9ea18d738ad4a2653631558931b0f1fde4dd58c436d19686dc28"
	if got := hex.EncodeToString(p.BytesMontgomery()); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBytesMontgomeryInfinity(t *testing.T) {
	p := NewIdentityPoint()
	want := "0000000000000000000000000000000000000000000000000000000000000000"
	if got := hex.EncodeToString(p.BytesMontgomery()); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMultByCofactor(t *testing.T) {
	lowOrderBytes := "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"
	lowOrder, err := (&Point{}).SetBytes(decodeHex(lowOrderBytes))
	if err != nil {
		t.Fatal(err)
	}

	if p := (&Point{}).MultByCofactor(lowOrder); p.Equal(NewIdentityPoint()) != 1 {
		t.Errorf("expected low order point * cofactor to be the identity")
	}

	f := func(scalar [64]byte) bool {
		s := NewScalar().SetUniformBytes(scalar[:])
		p := (&Point{}).ScalarBaseMult(s)
		p8 := (&Point{}).MultByCofactor(p)
		checkOnCurve(t, p8)

		// 8 * p == (8 * s) * B
		s.Multiply(s, &Scalar{[32]byte{8}})
		pp := (&Point{}).ScalarBaseMult(s)
		if p8.Equal(pp) != 1 {
			return false
		}

		// 8 * p == 8 * (lowOrder + p)
		pp.Add(p, lowOrder)
		pp.MultByCofactor(pp)
		if p8.Equal(pp) != 1 {
			return false
		}

		// 8 * p == p + p + p + p + p + p + p + p
		pp.Set(NewIdentityPoint())
		for i := 0; i < 8; i++ {
			pp.Add(pp, p)
		}
		return p8.Equal(pp) == 1
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
