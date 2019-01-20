// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import x "github.com/gtank/ristretto255/internal/edwards25519/internal/edwards25519"

// Expose some types and functions from the x/crypto code to ristretto255.

type ExtendedGroupElement = x.ExtendedGroupElement
type FieldElement = x.FieldElement

var FeMul = x.FeMul
var FeSquare = x.FeSquare
var FeNeg = x.FeNeg
var FeIsNegative = x.FeIsNegative
