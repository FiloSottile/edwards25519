// Copyright (c) 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,gc,!purego

package edwards25519

//go:noescape
func carryPropagate(v *fieldElement)

func (v *fieldElement) carryPropagate() *fieldElement {
	carryPropagate(v)
	return v
}
