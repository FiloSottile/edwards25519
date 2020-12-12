// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"bytes"
	"encoding/hex"
	"math/big"
	mathrand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Generate returns a valid (reduced modulo l) Scalar with a distribution
// weighted towards high, low, and edge values.
func (Scalar) Generate(rand *mathrand.Rand, size int) reflect.Value {
	s := scZero
	diceRoll := rand.Intn(100)
	switch {
	case diceRoll == 0:
	case diceRoll == 1:
		s = scOne
	case diceRoll == 2:
		s = scMinusOne
	case diceRoll < 5:
		// Generate a low scalar in [0, 2^125).
		rand.Read(s.s[:16])
		s.s[15] &= (1 << 5) - 1
	case diceRoll < 10:
		// Generate a high scalar in [2^252, 2^252 + 2^124).
		s.s[31] = 1 << 4
		rand.Read(s.s[:16])
		s.s[15] &= (1 << 4) - 1
	default:
		// Generate a valid scalar in [0, l) by returning [0, 2^252) which has a
		// negligibly different distribution (the former has a 2^-127.6 chance
		// of being out of the latter range).
		rand.Read(s.s[:])
		s.s[31] &= (1 << 4) - 1
	}
	return reflect.ValueOf(s)
}

func TestScalarGenerate(t *testing.T) {
	f := func(sc Scalar) bool {
		return isReduced(&sc)
	}
	if err := quick.Check(f, quickCheckConfig1024); err != nil {
		t.Errorf("generated unreduced scalar: %v", err)
	}
}

func TestScalarSetCanonicalBytes(t *testing.T) {
	f1 := func(in [32]byte, sc Scalar) bool {
		// Mask out top 4 bits to guarantee value falls in [0, l).
		in[len(in)-1] &= (1 << 4) - 1
		if _, err := sc.SetCanonicalBytes(in[:]); err != nil {
			return false
		}
		return bytes.Equal(in[:], sc.Bytes()) && isReduced(&sc)
	}
	if err := quick.Check(f1, quickCheckConfig1024); err != nil {
		t.Errorf("failed bytes->scalar->bytes round-trip: %v", err)
	}

	f2 := func(sc1, sc2 Scalar) bool {
		if _, err := sc2.SetCanonicalBytes(sc1.Bytes()); err != nil {
			return false
		}
		return sc1 == sc2
	}
	if err := quick.Check(f2, quickCheckConfig1024); err != nil {
		t.Errorf("failed scalar->bytes->scalar round-trip: %v", err)
	}

	b := scMinusOne.s
	b[31] += 1
	s := scOne
	if out, err := s.SetCanonicalBytes(b[:]); err == nil {
		t.Errorf("SetCanonicalBytes worked on a non-canonical value")
	} else if s != scOne {
		t.Errorf("SetCanonicalBytes modified its receiver")
	} else if out != nil {
		t.Errorf("SetCanonicalBytes did not return nil with an error")
	}
}

func TestScalarSetUniformBytes(t *testing.T) {
	mod, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	mod.Add(mod, new(big.Int).Lsh(big.NewInt(1), 252))
	f := func(in [64]byte, sc Scalar) bool {
		sc.SetUniformBytes(in[:])
		if !isReduced(&sc) {
			return false
		}
		scBig := bigIntFromLittleEndianBytes(sc.s[:])
		inBig := bigIntFromLittleEndianBytes(in[:])
		return inBig.Mod(inBig, mod).Cmp(scBig) == 0
	}
	if err := quick.Check(f, quickCheckConfig1024); err != nil {
		t.Error(err)
	}
}

func TestScalarSetBytesWithClamping(t *testing.T) {
	// Generated with libsodium.js 1.0.18 crypto_scalarmult_base.
	// Replace with crypto_scalarmult_ed25519_base vectors once
	// https://github.com/jedisct1/libsodium.js/issues/256 is fixed.

	random := "633d368491364dc9cd4c1bf891b1d59460face1644813240a313e61f2c88216e"
	s := (&Scalar{}).SetBytesWithClamping(decodeHex(random))
	p := (&Point{}).ScalarBaseMult(s)
	want := "f39e4e2953998c47237364569fa7356ce4d22f9ae51aa8bb40d088fff7c38057"
	if got := hex.EncodeToString(p.BytesMontgomery()); got != want {
		t.Errorf("random: got %q, want %q", got, want)
	}

	zero := "0000000000000000000000000000000000000000000000000000000000000000"
	s = (&Scalar{}).SetBytesWithClamping(decodeHex(zero))
	p = (&Point{}).ScalarBaseMult(s)
	want = "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	if got := hex.EncodeToString(p.BytesMontgomery()); got != want {
		t.Errorf("zero: got %q, want %q", got, want)
	}

	one := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	s = (&Scalar{}).SetBytesWithClamping(decodeHex(one))
	p = (&Point{}).ScalarBaseMult(s)
	want = "847c0d2c375234f365e660955187a3735a0f7613d1609d3a6a4d8c53aeaa5a22"
	if got := hex.EncodeToString(p.BytesMontgomery()); got != want {
		t.Errorf("one: got %q, want %q", got, want)
	}
}

func bigIntFromLittleEndianBytes(b []byte) *big.Int {
	bb := make([]byte, len(b))
	for i := range b {
		bb[i] = b[len(b)-i-1]
	}
	return new(big.Int).SetBytes(bb)
}

func TestScalarMulDistributesOverScalarAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z Scalar) bool {
		// Compute t1 = (x+y)*z
		var t1 Scalar
		t1.Add(&x, &y)
		t1.Multiply(&t1, &z)

		// Compute t2 = x*z + y*z
		var t2 Scalar
		var t3 Scalar
		t2.Multiply(&x, &z)
		t3.Multiply(&y, &z)
		t2.Add(&t2, &t3)

		return t1 == t2 && isReduced(&t1) && isReduced(&t3)
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig1024); err != nil {
		t.Error(err)
	}
}

func TestScalarAddLikeSubNeg(t *testing.T) {
	addLikeSubNeg := func(x, y Scalar) bool {
		// Compute t1 = x - y
		var t1 Scalar
		t1.Subtract(&x, &y)

		// Compute t2 = -y + x
		var t2 Scalar
		t2.Negate(&y)
		t2.Add(&t2, &x)

		return t1 == t2 && isReduced(&t1)
	}

	if err := quick.Check(addLikeSubNeg, quickCheckConfig1024); err != nil {
		t.Error(err)
	}
}

func TestScalarNonAdjacentForm(t *testing.T) {
	s := Scalar{[32]byte{
		0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d,
		0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8, 0x26, 0x4d,
		0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1,
		0x58, 0x9e, 0x7b, 0x7f, 0x23, 0x76, 0xef, 0x09,
	}}
	expectedNaf := [256]int8{
		0, 13, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, -11, 0, 0, 0, 0, 3, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 9, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 11, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0,
		-9, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 9, 0,
		0, 0, 0, -15, 0, 0, 0, 0, -7, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, -3, 0,
		0, 0, 0, -11, 0, 0, 0, 0, -7, 0, 0, 0, 0, -13, 0, 0, 0, 0, 11, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, -15, 0, 0, 0, 0, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0,
		0, 0, 0, 11, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 7,
		0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	}

	sNaf := s.nonAdjacentForm(5)

	for i := 0; i < 256; i++ {
		if expectedNaf[i] != sNaf[i] {
			t.Errorf("Wrong digit at position %d, got %d, expected %d", i, sNaf[i], expectedNaf[i])
		}
	}
}

type notZeroScalar Scalar

func (notZeroScalar) Generate(rand *mathrand.Rand, size int) reflect.Value {
	var s Scalar
	for s == scZero {
		s = Scalar{}.Generate(rand, size).Interface().(Scalar)
	}
	return reflect.ValueOf(notZeroScalar(s))
}

func TestScalarInvert(t *testing.T) {
	invertWorks := func(xInv Scalar, x notZeroScalar) bool {
		xInv.Invert((*Scalar)(&x))
		var check Scalar
		check.Multiply((*Scalar)(&x), &xInv)
		return check == scOne && isReduced(&xInv)
	}

	if err := quick.Check(invertWorks, quickCheckConfig32); err != nil {
		t.Error(err)
	}
}

func TestScalarEqual(t *testing.T) {
	if scOne.Equal(&scMinusOne) == 1 {
		t.Errorf("scOne.Equal(&scMinusOne) is true")
	}
	if scMinusOne.Equal(&scMinusOne) == 0 {
		t.Errorf("scMinusOne.Equal(&scMinusOne) is false")
	}
}
