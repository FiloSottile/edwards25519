// +build amd64,!noasm

package radix51

// go:noescape
func FeMul(out, a, b *FieldElement)
