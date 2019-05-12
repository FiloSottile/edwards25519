// Copyright 2019 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"

	"github.com/gtank/ristretto255/internal/radix51"
)

var (
	// The Ed25519 basepoint.
	B = ProjP3{
		X: radix51.FieldElement([5]uint64{1738742601995546, 1146398526822698, 2070867633025821, 562264141797630, 587772402128613}),
		Y: radix51.FieldElement([5]uint64{1801439850948184, 1351079888211148, 450359962737049, 900719925474099, 1801439850948198}),
		Z: radix51.FieldElement([5]uint64{1, 0, 0, 0, 0}),
		T: radix51.FieldElement([5]uint64{1841354044333475, 16398895984059, 755974180946558, 900171276175154, 1821297809914039}),
	}
)

func TestAddSubNegOnBasePoint(t *testing.T) {
	var B, Bneg ProjP3
	var tmpP2 ProjP2
	var tmpP1xP1 ProjP1xP1
	var tmpCached ProjCached

	Bneg.Neg(&B)

	var checkLhs, checkRhs, zero ProjP3
	zero.Zero()

	tmpCached.FromP3(&B)
	tmpP1xP1.Add(&B, &tmpCached)
	checkLhs.FromP1xP1(&tmpP1xP1)
	tmpP2.FromP3(&B)
	tmpP1xP1.Double(&tmpP2)
	checkRhs.FromP1xP1(&tmpP1xP1)
	if checkLhs.Equal(&checkRhs) != 1 {
		t.Error("B + B != [2]B")
	}

	tmpCached.FromP3(&B)
	tmpP1xP1.Sub(&B, &tmpCached)
	checkLhs.FromP1xP1(&tmpP1xP1)
	tmpCached.FromP3(&Bneg)
	tmpP1xP1.Add(&B, &tmpCached)
	checkRhs.FromP1xP1(&tmpP1xP1)
	if checkLhs.Equal(&checkRhs) != 1 {
		t.Error("B - B != B + (-B)")
	}
	if zero.Equal(&checkLhs) != 1 {
		t.Error("B - B != 0")
	}
	if zero.Equal(&checkRhs) != 1 {
		t.Error("B + (-B) != 0")
	}
}
