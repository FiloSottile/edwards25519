// Copyright 2019 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
)

func TestAddSubNegOnBasePoint(t *testing.T) {
	var Bneg ProjP3
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
