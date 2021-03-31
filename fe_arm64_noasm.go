// Copyright (c) 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !arm64 !gc purego

package edwards25519

func (v *fieldElement) carryPropagate() *fieldElement {
	return v.carryPropagateGeneric()
}
