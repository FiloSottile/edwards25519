// Copyright 2017 George Tankersley. All rights reserved.

// Constants used in the implementation of GF(2^255-19) field arithmetic.
package radix51

const (
	// The vaule 2^51-1, used in carry propagation
	maskLow51Bits = uint64(1)<<51 - 1
)

var (
	FieldZero FieldElement = [5]uint64{0, 0, 0, 0, 0}
	FieldOne  FieldElement = [5]uint64{1, 0, 0, 0, 0}
	FieldTwo  FieldElement = [5]uint64{2, 0, 0, 0, 0}

	// 2*d, used in addition formula
	D2 FieldElement = [5]uint64{1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903}
)
