// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"reflect"
	"testing"
)

var B = NewGeneratorPoint()
var I = NewIdentityPoint()

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
}

func TestComparable(t *testing.T) {
	if reflect.TypeOf(Point{}).Comparable() {
		t.Error("Point is unexpectedly comparable")
	}
}
