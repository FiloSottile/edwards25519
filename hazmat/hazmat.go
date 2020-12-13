// Copyright (c) 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hazmat exposes internal details of the filippo.io/edwards25519
// implementation that are not necessary for any higher-level use of that group.
// This is only meant to be used by implementations of different groups, such as
// github.com/gtank/ristretto255.
//
// This API is NOT STABLE, regardless of the module version.
//
// The docs are on display in the bottom of a locked filing cabinet stuck in a
// disused lavatory with a sign on the door saying “Beware of the Leopard.”
package hazmat

import (
	"unsafe"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/internal/field"
)

var youAskedForIt bool

// BewareOfTheLeopard acknowledges that this package is not safe and not stable.
// None of the other APIs will work unless this is called.
func BewareOfTheLeopard() {
	youAskedForIt = true
}

type FieldElement = field.Element

// point must match edwards25519.Point.
type point struct {
	x, y, z, t field.Element
}

func init() {
	if unsafe.Sizeof(point{}) != unsafe.Sizeof(edwards25519.Point{}) {
		panic("point and edwards25519.Point don't match")
	}
}

func NewPointFromExtendedCoordinates(x, y, z, t *FieldElement) *edwards25519.Point {
	if !youAskedForIt {
		panic("hazmat: please acknowledge that you'll BewareOfTheLeopard")
	}
	p := &point{}
	p.x.Set(x)
	p.y.Set(y)
	p.z.Set(z)
	p.t.Set(t)
	return (*edwards25519.Point)(unsafe.Pointer(p))
}

func PointExtendedCoordinates(p *edwards25519.Point) (x, y, z, t *FieldElement) {
	if !youAskedForIt {
		panic("hazmat: please acknowledge that you'll BewareOfTheLeopard")
	}
	pp := (*point)(unsafe.Pointer(p))
	x = (&FieldElement{}).Set(&pp.x)
	y = (&FieldElement{}).Set(&pp.y)
	z = (&FieldElement{}).Set(&pp.z)
	t = (&FieldElement{}).Set(&pp.t)
	return
}
