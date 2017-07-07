package group

import "github.com/gtank/ed25519/internal/radix51"

var (
	// d, a constant in the curve equation
	D radix51.FieldElement = [5]uint64{929955233495203, 466365720129213, 1662059464998953, 2033849074728123, 1442794654840575}

	// 2*d, used in addition formula
	D2 radix51.FieldElement = [5]uint64{1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903}
)
