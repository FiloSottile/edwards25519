package scalar

import (
	"bytes"
	"testing"
	"testing/quick"
)

// quickCheckConfig will make each quickcheck test run (1024 * -quickchecks)
// times. The default value of -quickchecks is 100.
var quickCheckConfig = &quick.Config{MaxCountScale: 1 << 10}

func TestFromBytesRoundTrip(t *testing.T) {
	f1 := func(in, out [32]byte, sc Scalar) bool {
		in[len(in)-1] &= (1 << 4) - 1 // Mask out top 4 bits for 252-bit numbers
		sc.FromBytes(in[:])
		sc.Bytes(out[:0])
		return bytes.Equal(in[:], out[:]) && sc.IsCanonical()
	}
	if err := quick.Check(f1, nil); err != nil {
		t.Errorf("failed bytes->scalar->bytes round-trip: %v", err)
	}

	f2 := func(sc1, sc2 Scalar, out [32]byte) bool {
		sc1.Bytes(out[:0])
		sc2.FromBytes(out[:])

		sc1.reduce()
		sc2.reduce()
		return sc1 == sc2
	}
	if err := quick.Check(f2, nil); err != nil {
		t.Errorf("failed scalar->bytes->scalar round-trip: %v", err)
	}
}

func TestMulDistributesOverAdd(t *testing.T) {
	mulDistributesOverAdd := func(x, y, z Scalar) bool {
		// Compute t1 = (x+y)*z
		var t1 Scalar
		t1.Add(&x, &y)
		t1.Mul(&t1, &z)

		// Compute t2 = x*z + y*z
		var t2 Scalar
		var t3 Scalar
		t2.Mul(&x, &z)
		t3.Mul(&y, &z)
		t2.Add(&t2, &t3)

		return t1.Equal(&t2) == 1 && t1.IsCanonical() && t2.IsCanonical()
	}

	if err := quick.Check(mulDistributesOverAdd, quickCheckConfig); err != nil {
		t.Error(err)
	}
}
