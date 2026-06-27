package hdwallet

// CREATE2Address computes the address a CREATE2 deployment will land at.
//
//	deployer — address calling CREATE2 (20 bytes)
//	salt     — 32-byte salt
//	initCode — contract init bytecode
//
// Formula: keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(initCode))[12:]
func CREATE2Address(deployer []byte, salt [32]byte, initCode []byte) []byte {
	initHash := keccak256(initCode)
	pre := make([]byte, 1+20+32+32)
	pre[0] = 0xff
	copy(pre[1:], deployer)
	copy(pre[21:], salt[:])
	copy(pre[53:], initHash)
	return keccak256(pre)[12:]
}
