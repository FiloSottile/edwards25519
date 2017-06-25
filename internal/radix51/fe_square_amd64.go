// +build amd64,!noasm

package radix51

// go:noescape
func FeSquare(out, x *FieldElement)
