// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!purego

package base

//go:noescape
func feMul(out, a, b *FieldElement)

//go:noescape
func feSquare(out, x *FieldElement)
