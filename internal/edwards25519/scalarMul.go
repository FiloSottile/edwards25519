// Copyright (c) 2019 Henry de Valence.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"github.com/gtank/ristretto255/internal/scalar"
)

// Set v to x*B, where B is the Ed25519 basepoint, and return v.
//
// The scalar multiplication is done in constant time.
func (v *ProjP3) BasepointMul(x *scalar.Scalar) *ProjP3 {
	// Write x = sum(x_i * 16^i) so  x*B = sum( B*x_i*16^i )
	// as described in the Ed25519 paper
	//
	// Group even and odd coefficients
	// x*B     = x_0*16^0*B + x_2*16^2*B + ... + x_62*16^62*B
	//         + x_1*16^1*B + x_3*16^3*B + ... + x_63*16^63*B
	// x*B     = x_0*16^0*B + x_2*16^2*B + ... + x_62*16^62*B
	//    + 16*( x_1*16^0*B + x_3*16^2*B + ... + x_63*16^62*B)
	//
	// We use a lookup table for each i to get x_i*16^(2*i)*B
	// and do four doublings to multiply by 16.
	digits := x.SignedRadix16()

	multiple := &AffineCached{}
	tmp1 := &ProjP1xP1{}
	tmp2 := &ProjP2{}

	// Accumulate the odd components first
	v.Zero()
	for i := 1; i < 64; i += 2 {
		basepointTable[i/2].SelectInto(multiple, digits[i])
		tmp1.AddAffine(v, multiple)
		v.FromP1xP1(tmp1)
	}

	// Multiply by 16
	tmp2.FromP3(v)       // tmp2 =    v in P2 coords
	tmp1.Double(tmp2)    // tmp1 =  2*v in P1xP1 coords
	tmp2.FromP1xP1(tmp1) // tmp2 =  2*v in P2 coords
	tmp1.Double(tmp2)    // tmp1 =  4*v in P1xP1 coords
	tmp2.FromP1xP1(tmp1) // tmp2 =  4*v in P2 coords
	tmp1.Double(tmp2)    // tmp1 =  8*v in P1xP1 coords
	tmp2.FromP1xP1(tmp1) // tmp2 =  8*v in P2 coords
	tmp1.Double(tmp2)    // tmp1 = 16*v in P1xP1 coords
	v.FromP1xP1(tmp1)    // now v = 16*(odd components)

	// Accumulate the even components
	for i := 0; i < 64; i += 2 {
		basepointTable[i/2].SelectInto(multiple, digits[i])
		tmp1.AddAffine(v, multiple)
		v.FromP1xP1(tmp1)
	}

	return v
}

// Set v to x*Q, and return v.  v and q may alias.
//
// The scalar multiplication is done in constant time.
func (v *ProjP3) ScalarMul(x *scalar.Scalar, q *ProjP3) *ProjP3 {
	var table ProjLookupTable
	table.FromP3(q)
	// v and q could alias, but once the table is built we can clobber v.
	v.Zero()

	// Write x = sum(x_i * 16^i)
	// so  x*Q = sum( Q*x_i*16^i )
	//         = Q*x_0 + 16*(Q*x_1 + 16*( ... + Q*x_63) ... )
	//           <------compute inside out---------
	//
	// We use the lookup table to get the x_i*Q values
	// and do four doublings to compute 16*Q
	digits := x.SignedRadix16()

	// Unwrap first loop iteration to save computing 16*identity
	multiple := &ProjCached{}
	tmp1 := &ProjP1xP1{}
	tmp2 := &ProjP2{}
	table.SelectInto(multiple, digits[63])
	tmp1.Add(v, multiple) // tmp1 = x_63*Q in P1xP1 coords
	for i := 62; i >= 0; i-- {
		tmp2.FromP1xP1(tmp1) // tmp2 =    (prev) in P2 coords
		tmp1.Double(tmp2)    // tmp1 =  2*(prev) in P1xP1 coords
		tmp2.FromP1xP1(tmp1) // tmp2 =  2*(prev) in P2 coords
		tmp1.Double(tmp2)    // tmp1 =  4*(prev) in P1xP1 coords
		tmp2.FromP1xP1(tmp1) // tmp2 =  4*(prev) in P2 coords
		tmp1.Double(tmp2)    // tmp1 =  8*(prev) in P1xP1 coords
		tmp2.FromP1xP1(tmp1) // tmp2 =  8*(prev) in P2 coords
		tmp1.Double(tmp2)    // tmp1 = 16*(prev) in P1xP1 coords
		v.FromP1xP1(tmp1)    //    v = 16*(prev) in P3 coords
		table.SelectInto(multiple, digits[i])
		tmp1.Add(v, multiple) // tmp1 = x_i*Q + 16*(prev) in P1xP1 coords
	}
	v.FromP1xP1(tmp1)
	return v
}

// Set v to a*A + b*B, where B is the Ed25519 basepoint, and return v.
//
// The scalar multiplication is done in variable time.
func (v *ProjP3) VartimeDoubleBaseMul(a, b *scalar.Scalar, A *ProjP3) *ProjP3 {
	panic("unimplemented")
	return v
}

// Set v to the result of a multiscalar multiplication and return v.
//
// The multiscalar multiplication is sum(scalars[i]*points[i]).
//
// The multiscalar multiplication is performed in constant time.
func (v *ProjP3) MultiscalarMul(scalars []scalar.Scalar, points []*ProjP3) *ProjP3 {
	panic("unimplemented")
	return v
}

// Set v to the result of a multiscalar multiplication and return v.
//
// The multiscalar multiplication is sum(scalars[i]*points[i]).
//
// The multiscalar multiplication is performed in variable time.
func (v *ProjP3) VartimeMultiscalarMul(scalars []scalar.Scalar, points []*ProjP3) *ProjP3 {
	panic("unimplemented")
	return v
}
