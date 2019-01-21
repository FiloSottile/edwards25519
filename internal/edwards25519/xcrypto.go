// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"github.com/gtank/ristretto255/internal/edwards25519/internal/group"
	"github.com/gtank/ristretto255/internal/edwards25519/internal/radix51"
)

// Expose some types and functions from the internal package to ristretto255.

type ExtendedGroupElement = group.ExtendedGroupElement
type FieldElement = radix51.FieldElement

var FeMul = radix51.FeMul
var FeSquare = radix51.FeSquare
var FeNeg = radix51.FeNeg
