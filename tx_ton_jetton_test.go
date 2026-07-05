package hdwallet

import (
	"encoding/hex"
	"testing"

	txton "github.com/ranjbar-dev/hd-wallet/txproto/ton"
)

// TON TEP-74 jetton (fungible token) transfer signing — vector-pinned tests.
//
// Source: Trust Wallet Core, rust/tw_tests/tests/chains/ton/ton_sign.rs,
// tests "test_ton_sign_transfer_jettons" and
// "test_ton_sign_transfer_jettons_with_comment" (fetched 2026-07 from the
// raw.githubusercontent.com master file).
//
// In a jetton transfer the Transfer.dest is the SENDER's jetton wallet address
// (the contract the internal message is sent to); the internal-message body is
// the TEP-74 transfer body:
//   op=0x0f8a7ea5 u32 || query_id u64 || jetton amount (grams) || to_owner addr
//   || response addr || custom_payload=0 || forward_ton_amount (grams)
//   || forward_payload (inline op=0+comment, or empty).

// TestSignTxTONJetton pins a jetton transfer (deploy, seqno==0, no comment)
// byte-for-byte to TWC "test_ton_sign_transfer_jettons".
func TestSignTxTONJetton(t *testing.T) {
	key, _ := hex.DecodeString("c054900a527538c1b4325688a421c0469b171c29f23a62da216e90b0df2412ee")
	w, err := FromPrivateKeyBytes(key, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txton.SigningInput{
		SequenceNumber: 0,
		// TWC vector signs with expire_at = 0xFFFFFFFF (the authoritative
		// `encoded` BoC carries ffffffff after the subwallet_id constant).
		ExpireAt: 0xFFFFFFFF,
		Transfer: &txton.Transfer{
			Dest:       "EQBiaD8PO1NwfbxSkwbcNT9rXDjqhiIvXWymNO-edV0H5lja",
			Amount:     100 * 1000 * 1000,
			Mode:       3,
			Bounceable: true,
			JettonTransfer: &txton.JettonTransfer{
				QueryId:         69,
				JettonAmount:    1000 * 1000 * 1000,
				ToOwner:         "EQAFwMs5ha8OgZ9M4hQr80z9NkE7rGxUpE1hCFndiY6JnDx8",
				ResponseAddress: "EQBaKIMq5Am2p_rfR1IFTwsNWHxBkOpLTmwUain5Fj4llTXk",
				ForwardAmount:   1,
			},
		},
	}

	const wantEncoded = "te6ccgICABoAAQAABCMAAAJFiAC0UQZVyBNtT/W+jqQKnhYasPiDIdSWnNgo1FPyLHxLKh4ABAABAZz3iNHD1z2mxbtpFAtmbVevYMnB4yHPkF3WAsL3KHcrqCw0SWezOg4lVz1zzSReeFDx98ByAqY9+eR5VF3xyugAKamjF/////8AAAAAAAMAAgFoYgAxNB+Hnam4Pt4pSYNuGp+1rhx1QxEXrrZTGnfPOq6D8yAvrwgAAAAAAAAAAAAAAAAAAQADAKoPin6lAAAAAAAAAEVDuaygCAALgZZzC14dAz6ZxChX5pn6bIJ3WNipSJrCELO7Ex0TOQAWiiDKuQJtqf630dSBU8LDVh8QZDqS05sFGop+RY+JZUICAgE0AAYABQBRAAAAACmpoxfOamBhePRNnx/pqQViBzW0dDCy/+1WLV1VhgbVTL6i30ABFP8A9KQT9LzyyAsABwIBIAANAAgE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8ADAALAAoACQAK9ADJ7VQAbIEBCNcY+gDTPzBSJIEBCPRZ8qeCEGRzdHJwdIAYyMsFywJQBc8WUAP6AhPLassfEss/yXP7AABwgQEI1xj6ANM/yFQgR4EBCPRR8qeCEG5vdGVwdIAYyMsFywJQBs8WUAT6AhTLahLLH8s/yXP7AAIAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwICAUgAFwAOAgEgABAADwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgEgABIAEQARuMl+1E0NcLH4AgFYABYAEwIBIAAVABQAGa8d9qJoQBBrkOuFj8AAGa3OdqJoQCBrkOuF/8AAPbKd+1E0IEBQNch9AQwAsjKB8v/ydABgQEI9ApvoTGAC5tAB0NMDIXGwkl8E4CLXScEgkl8E4ALTHyGCEHBsdWe9IoIQZHN0cr2wkl8F4AP6QDAg+kQByMoHy//J0O1E0IEBQNch9AQwXIEBCPQKb6Exs5JfB+AF0z/IJYIQcGx1Z7qSODDjDQOCEGRzdHK6kl8G4w0AGQAYAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+IAeAH6APQEMPgnbyIwUAqhIb7y4FCCEHBsdWeDHrFwgBhQBMsFJs8WWPoCGfQAy2kXyx9SYMs/IMmAQPsABg=="
	const wantHash = "3e4dac37acdc99ca670b3747ab2730e818727d9d25c80d3987abe501356d0da0"

	out, err := w.SignTransaction(TON, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	got := out.(*txton.SigningOutput)
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
	if got.Hash != wantHash {
		t.Errorf("hash mismatch\n got: %s\nwant: %s", got.Hash, wantHash)
	}
}

// TestSignTxTONJettonWithComment pins a jetton transfer carrying an inline
// forward-payload text comment (seqno==1, no deploy) byte-for-byte to TWC
// "test_ton_sign_transfer_jettons_with_comment".
func TestSignTxTONJettonWithComment(t *testing.T) {
	key, _ := hex.DecodeString("c054900a527538c1b4325688a421c0469b171c29f23a62da216e90b0df2412ee")
	w, err := FromPrivateKeyBytes(key, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txton.SigningInput{
		SequenceNumber: 1,
		ExpireAt:       1787693046,
		Transfer: &txton.Transfer{
			Dest:       "EQBiaD8PO1NwfbxSkwbcNT9rXDjqhiIvXWymNO-edV0H5lja",
			Amount:     100 * 1000 * 1000,
			Mode:       3,
			Bounceable: true,
			Comment:    "test comment",
			JettonTransfer: &txton.JettonTransfer{
				QueryId:         0,
				JettonAmount:    500 * 1000 * 1000,
				ToOwner:         "EQAFwMs5ha8OgZ9M4hQr80z9NkE7rGxUpE1hCFndiY6JnDx8",
				ResponseAddress: "EQBaKIMq5Am2p_rfR1IFTwsNWHxBkOpLTmwUain5Fj4llTXk",
				ForwardAmount:   1,
			},
		},
	}

	const wantEncoded = "te6ccgICAAQAAQAAARgAAAFFiAC0UQZVyBNtT/W+jqQKnhYasPiDIdSWnNgo1FPyLHxLKgwAAQGcaIWVosi1XnveAmoG9y0/mPeNUqUu7GY76mdbRAaVeNeDOPDlh5M3BEb26kkc6XoYDekV60o2iOobN+TGS76jBSmpoxdqjgf2AAAAAQADAAIBaGIAMTQfh52puD7eKUmDbhqfta4cdUMRF662Uxp3zzqug/MgL68IAAAAAAAAAAAAAAAAAAEAAwDKD4p+pQAAAAAAAAAAQdzWUAgAC4GWcwteHQM+mcQoV+aZ+myCd1jYqUiawhCzuxMdEzkAFoogyrkCban+t9HUgVPCw1YfEGQ6ktObBRqKfkWPiWVCAgAAAAB0ZXN0IGNvbW1lbnQ="
	const wantHash = "c98c205c8dd37d9a6ab5db6162f5b9d37cefa067de24a765154a5eb7a359f22f"

	out, err := w.SignTransaction(TON, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	got := out.(*txton.SigningOutput)
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
	if got.Hash != wantHash {
		t.Errorf("hash mismatch\n got: %s\nwant: %s", got.Hash, wantHash)
	}
}
