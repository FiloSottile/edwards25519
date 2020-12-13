// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,gc,!purego

package field

//go:noescape
func feMul(out, a, b *Element)

//go:noescape
func feSquare(out, x *Element)

func (v *Element) carryPropagate() *Element {
	return v.carryPropagateGeneric()
}
