package edwards25519

import (
	"github.com/gtank/ristretto255/internal/radix51"
	"testing"
)

var (
	B = ProjP3{
		X: radix51.FieldElement([5]uint64{426475514619346, 2063872706840040, 14628272888959, 107677749330612, 288339085807592}),
		Y: radix51.FieldElement([5]uint64{1934594822876571, 2049809580636559, 1991994783322914, 1758681962032007, 380046701118659}),
		Z: radix51.FieldElement([5]uint64{1, 0, 0, 0, 0}),
		T: radix51.FieldElement([5]uint64{410445769351754, 2235400917701188, 1495825632738689, 1351628537510093, 430502003771208}),
	}
)

func TestProjLookupTable(t *testing.T) {
	var table ProjLookupTable
	table.FromP3(&B)

	var tmp1, tmp2, tmp3 ProjCached
	table.SelectInto(&tmp1, 6)
	table.SelectInto(&tmp2, -2)
	table.SelectInto(&tmp3, -4)
	// Expect T1 + T2 + T3 = identity

	var accP1xP1 ProjP1xP1
	var accP3, check ProjP3
	accP3.Zero()
	check.Zero()

	accP1xP1.Add(&accP3, &tmp1)
	accP3.FromP1xP1(&accP1xP1)
	accP1xP1.Add(&accP3, &tmp2)
	accP3.FromP1xP1(&accP1xP1)
	accP1xP1.Add(&accP3, &tmp3)
	accP3.FromP1xP1(&accP1xP1)

	if accP3.Equal(&check) != 1 {
		t.Errorf("Sanity check on ProjLookupTable.SelectInto failed!  %x %x %x", tmp1, tmp2, tmp3)
	}
}

func TestAffineLookupTable(t *testing.T) {
	var table AffineLookupTable
	table.FromP3(&B)

	var tmp1, tmp2, tmp3 AffineCached
	table.SelectInto(&tmp1, 3)
	table.SelectInto(&tmp2, -7)
	table.SelectInto(&tmp3, 4)
	// Expect T1 + T2 + T3 = identity

	var accP1xP1 ProjP1xP1
	var accP3, check ProjP3
	accP3.Zero()
	check.Zero()

	accP1xP1.AddAffine(&accP3, &tmp1)
	accP3.FromP1xP1(&accP1xP1)
	accP1xP1.AddAffine(&accP3, &tmp2)
	accP3.FromP1xP1(&accP1xP1)
	accP1xP1.AddAffine(&accP3, &tmp3)
	accP3.FromP1xP1(&accP1xP1)

	if accP3.Equal(&check) != 1 {
		t.Errorf("Sanity check on ProjLookupTable.SelectInto failed!  %x %x %x", tmp1, tmp2, tmp3)
	}
}

func TestNafLookupTable5(t *testing.T) {
	var table NafLookupTable5
	table.FromP3(&B)

	var tmp1, tmp2, tmp3, tmp4 ProjCached
	table.SelectInto(&tmp1, 9)
	table.SelectInto(&tmp2, 11)
	table.SelectInto(&tmp3, 7)
	table.SelectInto(&tmp4, 13)
	// Expect T1 + T2 = T3 + T4

	var accP1xP1 ProjP1xP1
	var lhs, rhs ProjP3
	lhs.Zero()
	rhs.Zero()

	accP1xP1.Add(&lhs, &tmp1)
	lhs.FromP1xP1(&accP1xP1)
	accP1xP1.Add(&lhs, &tmp2)
	lhs.FromP1xP1(&accP1xP1)

	accP1xP1.Add(&rhs, &tmp3)
	rhs.FromP1xP1(&accP1xP1)
	accP1xP1.Add(&rhs, &tmp4)
	rhs.FromP1xP1(&accP1xP1)

	if lhs.Equal(&rhs) != 1 {
		t.Errorf("Sanity check on NafLookupTable5 failed")
	}
}

func TestNafLookupTable8(t *testing.T) {
	var table NafLookupTable8
	table.FromP3(&B)

	var tmp1, tmp2, tmp3, tmp4 AffineCached
	table.SelectInto(&tmp1, 49)
	table.SelectInto(&tmp2, 11)
	table.SelectInto(&tmp3, 35)
	table.SelectInto(&tmp4, 25)
	// Expect T1 + T2 = T3 + T4

	var accP1xP1 ProjP1xP1
	var lhs, rhs ProjP3
	lhs.Zero()
	rhs.Zero()

	accP1xP1.AddAffine(&lhs, &tmp1)
	lhs.FromP1xP1(&accP1xP1)
	accP1xP1.AddAffine(&lhs, &tmp2)
	lhs.FromP1xP1(&accP1xP1)

	accP1xP1.AddAffine(&rhs, &tmp3)
	rhs.FromP1xP1(&accP1xP1)
	accP1xP1.AddAffine(&rhs, &tmp4)
	rhs.FromP1xP1(&accP1xP1)

	if lhs.Equal(&rhs) != 1 {
		t.Errorf("Sanity check on NafLookupTable8 failed")
	}
}
