package edwards25519

import (
	"github.com/gtank/ristretto255/internal/radix51"
	"testing"
)

func TestAddSubNegOnBasePoint(t *testing.T) {

	basepoint := ExtendedGroupElement{
		X: radix51.FieldElement([5]uint64{426475514619346, 2063872706840040, 14628272888959, 107677749330612, 288339085807592}),
		Y: radix51.FieldElement([5]uint64{1934594822876571, 2049809580636559, 1991994783322914, 1758681962032007, 380046701118659}),
		Z: radix51.FieldElement([5]uint64{1, 0, 0, 0, 0}),
		T: radix51.FieldElement([5]uint64{410445769351754, 2235400917701188, 1495825632738689, 1351628537510093, 430502003771208}),
	}

	negBasepoint := ExtendedGroupElement{}

	negBasepoint.Neg(&basepoint)

	check1 := ExtendedGroupElement{}
	check1.Zero()
	check2 := ExtendedGroupElement{}
	check2.Zero()
	zero := ExtendedGroupElement{}
	zero.Zero()

	check1.Add(&basepoint, &negBasepoint)
	check2.Sub(&basepoint, &basepoint)

	if check1.Equal(&check2) != 1 {
		t.Error("B + (-B) != B - B")
	}

	if check1.Equal(&zero) != 1 {
		t.Error("B + (-B) != 0")
	}
}
