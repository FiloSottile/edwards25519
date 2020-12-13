// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package field

import (
	"testing"
	"testing/quick"
)

func checkAliasingOneArg(f func(v, x *Element) *Element) func(v, x Element) bool {
	return func(v, x Element) bool {
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

func checkAliasingTwoArgs(f func(v, x, y *Element) *Element) func(v, x, y Element) bool {
	return func(v, x, y Element) bool {
		x1, y1, v1 := x, y, Element{}

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
		oneArgF  func(v, x *Element) *Element
		twoArgsF func(v, x, y *Element) *Element
	}
	for _, tt := range []target{
		{name: "Abs", oneArgF: (*Element).Absolute},
		{name: "Invert", oneArgF: (*Element).Invert},
		{name: "Neg", oneArgF: (*Element).Negate},
		{name: "Set", oneArgF: (*Element).Set},
		{name: "Square", oneArgF: (*Element).Square},
		{
			name: "CondNeg0",
			oneArgF: func(v, x *Element) *Element {
				return (*Element).CondNegate(v, x, 0)
			},
		},
		{
			name: "CondNeg1",
			oneArgF: func(v, x *Element) *Element {
				return (*Element).CondNegate(v, x, 1)
			},
		},
		{name: "Mul", twoArgsF: (*Element).Multiply},
		{name: "Add", twoArgsF: (*Element).Add},
		{name: "Sub", twoArgsF: (*Element).Subtract},
		{
			name: "Select0",
			twoArgsF: func(v, x, y *Element) *Element {
				return (*Element).Select(v, x, y, 0)
			},
		},
		{
			name: "Select1",
			twoArgsF: func(v, x, y *Element) *Element {
				return (*Element).Select(v, x, y, 1)
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
