// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64 purego

package radix51

func feMul(v, x, y *FieldElement) { feMulGeneric(v, x, y) }

func feSquare(v, x *FieldElement) { feSquareGeneric(v, x) }
