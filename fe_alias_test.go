// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
	"testing/quick"
)

func checkAliasingOneArg(f func(v, x *fieldElement) *fieldElement) func(v, x fieldElement) bool {
	return func(v, x fieldElement) bool {
		x1, v1 := x, x

		// Calculate a reference f(x) without aliasing.
		if out := f(&v, &x); out != &v && isInBounds(out) {
			return false
		}

		// Test aliasing the argument and the receiver.
		if out := f(&v1, &v1); out != &v1 || v1 != v {
			return false
		}

		// Ensure the arguments was not modified.
		return x == x1
	}
}

func checkAliasingTwoArgs(f func(v, x, y *fieldElement) *fieldElement) func(v, x, y fieldElement) bool {
	return func(v, x, y fieldElement) bool {
		x1, y1, v1 := x, y, fieldElement{}

		// Calculate a reference f(x, y) without aliasing.
		if out := f(&v, &x, &y); out != &v && isInBounds(out) {
			return false
		}

		// Test aliasing the first argument and the receiver.
		v1 = x
		if out := f(&v1, &v1, &y); out != &v1 || v1 != v {
			return false
		}
		// Test aliasing the second argument and the receiver.
		v1 = y
		if out := f(&v1, &x, &v1); out != &v1 || v1 != v {
			return false
		}

		// Calculate a reference f(x, x) without aliasing.
		if out := f(&v, &x, &x); out != &v {
			return false
		}

		// Test aliasing the first argument and the receiver.
		v1 = x
		if out := f(&v1, &v1, &x); out != &v1 || v1 != v {
			return false
		}
		// Test aliasing the second argument and the receiver.
		v1 = x
		if out := f(&v1, &x, &v1); out != &v1 || v1 != v {
			return false
		}
		// Test aliasing both arguments and the receiver.
		v1 = x
		if out := f(&v1, &v1, &v1); out != &v1 || v1 != v {
			return false
		}

		// Ensure the arguments were not modified.
		return x == x1 && y == y1
	}
}

func TestAliasing(t *testing.T) {
	type target struct {
		name     string
		oneArgF  func(v, x *fieldElement) *fieldElement
		twoArgsF func(v, x, y *fieldElement) *fieldElement
	}
	for _, tt := range []target{
		{name: "Abs", oneArgF: (*fieldElement).Absolute},
		{name: "Invert", oneArgF: (*fieldElement).Invert},
		{name: "Neg", oneArgF: (*fieldElement).Negate},
		{name: "Set", oneArgF: (*fieldElement).Set},
		{name: "Square", oneArgF: (*fieldElement).Square},
		{
			name: "CondNeg0",
			oneArgF: func(v, x *fieldElement) *fieldElement {
				return (*fieldElement).condNeg(v, x, 0)
			},
		},
		{
			name: "CondNeg1",
			oneArgF: func(v, x *fieldElement) *fieldElement {
				return (*fieldElement).condNeg(v, x, 1)
			},
		},
		{name: "Mul", twoArgsF: (*fieldElement).Multiply},
		{name: "Add", twoArgsF: (*fieldElement).Add},
		{name: "Sub", twoArgsF: (*fieldElement).Subtract},
		{
			name: "Select0",
			twoArgsF: func(v, x, y *fieldElement) *fieldElement {
				return (*fieldElement).Select(v, x, y, 0)
			},
		},
		{
			name: "Select1",
			twoArgsF: func(v, x, y *fieldElement) *fieldElement {
				return (*fieldElement).Select(v, x, y, 1)
			},
		},
	} {
		var err error
		switch {
		case tt.oneArgF != nil:
			err = quick.Check(checkAliasingOneArg(tt.oneArgF), &quick.Config{MaxCountScale: 1 << 8})
		case tt.twoArgsF != nil:
			err = quick.Check(checkAliasingTwoArgs(tt.twoArgsF), &quick.Config{MaxCountScale: 1 << 8})
		}
		if err != nil {
			t.Errorf("%v: %v", tt.name, err)
		}
	}
}
