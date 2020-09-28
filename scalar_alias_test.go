// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"testing"
	"testing/quick"
)

func TestScalarAliasing(t *testing.T) {
	checkAliasingOneArg := func(f func(v, x *Scalar) *Scalar) func(v, x Scalar) bool {
		return func(v, x Scalar) bool {
			x1, v1 := x, x

			// Calculate a reference f(x) without aliasing.
			if out := f(&v, &x); out != &v {
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

	checkAliasingTwoArgs := func(f func(v, x, y *Scalar) *Scalar) func(v, x, y Scalar) bool {
		return func(v, x, y Scalar) bool {
			x1, y1, v1 := x, y, Scalar{}

			// Calculate a reference f(x, y) without aliasing.
			if out := f(&v, &x, &y); out != &v {
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

	type target struct {
		name     string
		oneArgF  func(v, x *Scalar) *Scalar
		twoArgsF func(v, x, y *Scalar) *Scalar
	}
	for _, tt := range []target{
		{name: "Invert", oneArgF: (*Scalar).Invert},
		{name: "Neg", oneArgF: (*Scalar).Negate},
		{name: "Mul", twoArgsF: (*Scalar).Multiply},
		{name: "Add", twoArgsF: (*Scalar).Add},
		{name: "Sub", twoArgsF: (*Scalar).Subtract},
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
