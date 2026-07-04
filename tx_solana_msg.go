package hdwallet

import "encoding/binary"

// Legacy Solana message compilation for multi-instruction transactions.
//
// solanaCompileMessage reproduces Trust Wallet Core's account ordering,
// verified byte-for-byte against ten TWC AnySigner vectors (durable-nonce
// transfer, create-token-account ×3, create-and-transfer ×3, nonce-account
// lifecycle ×3), including the dedup cases (funder == wallet,
// recipient == authority):
//
//  1. the fee payer, first and always writable signer
//  2. remaining writable signers, first-appearance order
//  3. writable non-signers, first-appearance order
//  4. readonly non-signers, first-appearance order
//  5. program ids not already referenced, appended readonly, instruction order
//
// Duplicate references merge flags (signer|=, writable|=). The single-shape
// builders in tx_solana.go predate this compiler and stay untouched; every
// message produced here is pinned by its own vector test.

// solanaAccountMeta is one account reference inside an instruction.
type solanaAccountMeta struct {
	pubkey   []byte
	signer   bool
	writable bool
}

// solanaInstruction is a program invocation with ordered account references.
type solanaInstruction struct {
	programID []byte
	accounts  []solanaAccountMeta
	data      []byte
}

// solanaCompileMessage serializes the legacy message for instrs, with payer as
// fee payer and blockhash in the recent-blockhash slot (the durable nonce
// VALUE when an AdvanceNonceAccount instruction leads).
func solanaCompileMessage(payer []byte, instrs []solanaInstruction, blockhash []byte) []byte {
	type slot struct {
		key      []byte
		signer   bool
		writable bool
	}
	var order []*slot
	index := map[string]*slot{}
	add := func(k []byte, signer, writable bool) {
		s, ok := index[string(k)]
		if !ok {
			s = &slot{key: k}
			index[string(k)] = s
			order = append(order, s)
		}
		s.signer = s.signer || signer
		s.writable = s.writable || writable
	}

	// Fee payer first; Solana requires it writable regardless of per-instruction flags.
	add(payer, true, true)
	for _, in := range instrs {
		for _, a := range in.accounts {
			add(a.pubkey, a.signer, a.writable)
		}
	}
	for _, in := range instrs {
		if _, ok := index[string(in.programID)]; !ok {
			add(in.programID, false, false)
		}
	}

	var keys [][]byte
	numSigners, numROSigned, numROUnsigned := 0, 0, 0
	for _, s := range order {
		if s.signer && s.writable {
			keys = append(keys, s.key)
			numSigners++
		}
	}
	for _, s := range order {
		if s.signer && !s.writable {
			keys = append(keys, s.key)
			numSigners++
			numROSigned++
		}
	}
	for _, s := range order {
		if !s.signer && s.writable {
			keys = append(keys, s.key)
		}
	}
	for _, s := range order {
		if !s.signer && !s.writable {
			keys = append(keys, s.key)
			numROUnsigned++
		}
	}

	pos := map[string]byte{}
	for i, k := range keys {
		pos[string(k)] = byte(i) // #nosec G115 -- key count is bounded far below 256 by tx size limits
	}

	var msg []byte
	msg = append(msg, byte(numSigners), byte(numROSigned), byte(numROUnsigned)) // #nosec G115 -- counts bounded by key count
	msg = append(msg, solanaCompactU16(len(keys))...)
	for _, k := range keys {
		msg = append(msg, k...)
	}
	msg = append(msg, blockhash...)
	msg = append(msg, solanaCompactU16(len(instrs))...)
	for _, in := range instrs {
		msg = append(msg, pos[string(in.programID)])
		msg = append(msg, solanaCompactU16(len(in.accounts))...)
		for _, a := range in.accounts {
			msg = append(msg, pos[string(a.pubkey)])
		}
		msg = append(msg, solanaCompactU16(len(in.data))...)
		msg = append(msg, in.data...)
	}
	return msg
}

// ---- instruction builders (account metas/data pinned by the vector decodes) ----

// solanaInstrSystemTransfer: system Transfer (index 2).
func solanaInstrSystemTransfer(from, to []byte, lamports uint64) solanaInstruction {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], solanaTransferInstruction)
	binary.LittleEndian.PutUint64(data[4:12], lamports)
	return solanaInstruction{
		programID: solanaSystemProgramID,
		accounts: []solanaAccountMeta{
			{pubkey: from, signer: true, writable: true},
			{pubkey: to, writable: true},
		},
		data: data,
	}
}

// solanaInstrAdvanceNonce: system AdvanceNonceAccount (index 4).
func solanaInstrAdvanceNonce(nonceAccount, authority, sysvarRBH []byte) solanaInstruction {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 4)
	return solanaInstruction{
		programID: solanaSystemProgramID,
		accounts: []solanaAccountMeta{
			{pubkey: nonceAccount, writable: true},
			{pubkey: sysvarRBH},
			{pubkey: authority, signer: true},
		},
		data: data,
	}
}

// solanaInstrTransferChecked: SPL TransferChecked (tag 12).
func solanaInstrTransferChecked(source, mint, dest, owner, tokenProgram []byte, amount uint64, decimals byte) solanaInstruction {
	data := make([]byte, 0, 10)
	data = append(data, solanaTokenTransferCheckedInstruction)
	amt := make([]byte, 8)
	binary.LittleEndian.PutUint64(amt, amount)
	data = append(data, amt...)
	data = append(data, decimals)
	return solanaInstruction{
		programID: tokenProgram,
		accounts: []solanaAccountMeta{
			{pubkey: source, writable: true},
			{pubkey: mint},
			{pubkey: dest, writable: true},
			{pubkey: owner, signer: true},
		},
		data: data,
	}
}

// solanaInstrCreateATA: ATA-program CreateAssociatedTokenAccount (empty data).
func solanaInstrCreateATA(funder, ata, wallet, mint, systemProgram, tokenProgram, rent, ataProgram []byte) solanaInstruction {
	return solanaInstruction{
		programID: ataProgram,
		accounts: []solanaAccountMeta{
			{pubkey: funder, signer: true, writable: true},
			{pubkey: ata, writable: true},
			{pubkey: wallet},
			{pubkey: mint},
			{pubkey: systemProgram},
			{pubkey: tokenProgram},
			{pubkey: rent},
		},
	}
}

// solanaInstrCreateAccount: system CreateAccount (index 0). The new account
// co-signs its own creation.
func solanaInstrCreateAccount(funder, newAccount []byte, lamports, space uint64, owner []byte) solanaInstruction {
	data := make([]byte, 20, 52)
	binary.LittleEndian.PutUint32(data[0:4], 0)
	binary.LittleEndian.PutUint64(data[4:12], lamports)
	binary.LittleEndian.PutUint64(data[12:20], space)
	data = append(data, owner...)
	return solanaInstruction{
		programID: solanaSystemProgramID,
		accounts: []solanaAccountMeta{
			{pubkey: funder, signer: true, writable: true},
			{pubkey: newAccount, signer: true, writable: true},
		},
		data: data,
	}
}

// solanaInstrInitNonce: system InitializeNonceAccount (index 6).
func solanaInstrInitNonce(nonceAccount, sysvarRBH, rent, authority []byte) solanaInstruction {
	data := make([]byte, 4, 36)
	binary.LittleEndian.PutUint32(data, 6)
	data = append(data, authority...)
	return solanaInstruction{
		programID: solanaSystemProgramID,
		accounts: []solanaAccountMeta{
			{pubkey: nonceAccount, writable: true},
			{pubkey: sysvarRBH},
			{pubkey: rent},
		},
		data: data,
	}
}

// solanaInstrWithdrawNonce: system WithdrawNonceAccount (index 5).
func solanaInstrWithdrawNonce(nonceAccount, recipient, sysvarRBH, rent, authority []byte, lamports uint64) solanaInstruction {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], 5)
	binary.LittleEndian.PutUint64(data[4:12], lamports)
	return solanaInstruction{
		programID: solanaSystemProgramID,
		accounts: []solanaAccountMeta{
			{pubkey: nonceAccount, writable: true},
			{pubkey: recipient, writable: true},
			{pubkey: sysvarRBH},
			{pubkey: rent},
			{pubkey: authority, signer: true},
		},
		data: data,
	}
}
