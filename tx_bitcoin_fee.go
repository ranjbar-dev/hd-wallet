package hdwallet

import "math"

// CPFPFee returns the fee a child tx must pay so that the parent+child package
// confirms at targetSatPerVbyte sat/vbyte. parentFeeAlreadyPaid is the fee the
// parent tx already included (satoshis); parentVsize and childVsize are virtual
// sizes in vbytes (use EstimateTxVsize). Returns 0 if the parent alone already
// meets or exceeds the target rate.
func CPFPFee(parentFeeAlreadyPaid, parentVsize, childVsize int64, targetSatPerVbyte float64) int64 {
	total := int64(math.Ceil(float64(parentVsize+childVsize) * targetSatPerVbyte))
	if child := total - parentFeeAlreadyPaid; child > 0 {
		return child
	}
	return 0
}
