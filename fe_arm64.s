// Copyright (c) 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,gc,!purego

#include "textflag.h"

// func carryPropagate(v *fieldElement)
TEXT ·carryPropagate(SB),NOFRAME|NOSPLIT,$0-8
	MOVD v+0(FP), R10

	LDP 0(R10), (R0, R1)
	LDP 16(R10), (R2, R3)
	MOVD 32(R10), R4

	// v.l1 += v.l0 >> 51
	// v.l0 &= maskLow51Bits
	ADD R0>>51, R1, R1
	AND $0x7ffffffffffff, R0, R0

	// v.l2 += v.l1 >> 51
	// v.l1 &= maskLow51Bits
	ADD R1>>51, R2, R2
	AND $0x7ffffffffffff, R1, R1

	// v.l3 += v.l2 >> 51
	// v.l2 &= maskLow51Bits
	ADD R2>>51, R3, R3
	AND $0x7ffffffffffff, R2, R2

	// v.l4 += v.l3 >> 51
	// v.l3 &= maskLow51Bits
	ADD R3>>51, R4, R4
	AND $0x7ffffffffffff, R3, R3

	// v.l0 += (v.l4 >> 51) * 19
	// v.l4 &= maskLow51Bits
	LSR $51, R4, R14
	MOVD $19, R19
	MADD R19, R0, R14, R0
	AND $0x7ffffffffffff, R4, R4

	STP (R0, R1), 0(R10)
	STP (R2, R3), 16(R10)
	MOVD R4, 32(R10)

	RET
