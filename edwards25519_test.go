// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
)

func TestAddSubNegOnBasePoint(t *testing.T) {
	Bneg := &Point{}
	tmpP2 := &projP2{}
	tmpP1xP1 := &projP1xP1{}
	tmpCached := &projCached{}

	Bneg.Negate(B)

	checkLhs, checkRhs := &Point{}, &Point{}
	zero := new(Point).Zero()

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
	if zero.Equal(checkLhs) != 1 {
		t.Error("B - B != 0")
	}
	if zero.Equal(checkRhs) != 1 {
		t.Error("B + (-B) != 0")
	}
}
