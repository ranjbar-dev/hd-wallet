package hdwallet

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// cosmosMultisigVector mirrors the JSON emitted by _oracle_cosmos (the
// reference cosmos-sdk implementation) — see testdata/cosmos_multisig_vector.json.
type cosmosMultisigVector struct {
	Threshold       int               `json:"threshold"`
	PubKeysHex      []string          `json:"pubkeys_hex"`
	MultisigAddress string            `json:"multisig_address"`
	AminoPubKeyHex  string            `json:"amino_pubkey_hex"`
	ToAddress       string            `json:"to_address"`
	ChainID         string            `json:"chain_id"`
	AccountNumber   uint64            `json:"account_number"`
	Sequence        uint64            `json:"sequence"`
	Memo            string            `json:"memo"`
	Denom           string            `json:"denom"`
	SendAmount      string            `json:"send_amount"`
	FeeAmount       string            `json:"fee_amount"`
	Gas             uint64            `json:"gas"`
	SignDocJSON     string            `json:"sign_doc_json"`
	SignerIndices   []int             `json:"signer_indices"`
	PartialSigsHex  map[string]string `json:"partial_sigs_hex"`
	TxRawBase64     string            `json:"tx_raw_base64"`
	TxIDHex         string            `json:"tx_id_hex"`
}

func loadCosmosMultisigVector(t *testing.T) cosmosMultisigVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/cosmos_multisig_vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v cosmosMultisigVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}
	return v
}

func (v cosmosMultisigVector) pubkeys(t *testing.T) [][]byte {
	t.Helper()
	out := make([][]byte, len(v.PubKeysHex))
	for i, h := range v.PubKeysHex {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 33 {
			t.Fatalf("pubkey %d: %v (len %d)", i, err, len(b))
		}
		out[i] = b
	}
	return out
}

// scalarPrivKey returns the 32-byte secp256k1 key with scalar value n — the
// oracle's deterministic test keys (hold no funds).
func scalarPrivKey(n byte) []byte {
	b := make([]byte, 32)
	b[31] = n
	return b
}

func (v cosmosMultisigVector) signingInput() *txcosmos.SigningInput {
	return &txcosmos.SigningInput{
		ChainId:       v.ChainID,
		AccountNumber: v.AccountNumber,
		Sequence:      v.Sequence,
		Memo:          v.Memo,
		Fee:           &txcosmos.Fee{Denom: v.Denom, Amount: v.FeeAmount, Gas: v.Gas},
		Send: &txcosmos.SendCoinsMessage{
			FromAddress: v.MultisigAddress,
			ToAddress:   v.ToAddress,
			Denom:       v.Denom,
			Amount:      v.SendAmount,
		},
	}
}

func TestCosmosMultisigAddressVector(t *testing.T) {
	v := loadCosmosMultisigVector(t)
	pubs := v.pubkeys(t)

	amino := cosmosMultisigAminoBytes(v.Threshold, pubs)
	if got := hex.EncodeToString(amino); got != v.AminoPubKeyHex {
		t.Fatalf("amino pubkey mismatch:\n got  %s\n want %s", got, v.AminoPubKeyHex)
	}
	addr, err := CosmosMultisigAddress("cosmos", v.Threshold, pubs)
	if err != nil {
		t.Fatalf("CosmosMultisigAddress: %v", err)
	}
	if addr != v.MultisigAddress {
		t.Fatalf("address = %s, want %s", addr, v.MultisigAddress)
	}
}

func TestSignCosmosMultisigPartialVector(t *testing.T) {
	v := loadCosmosMultisigVector(t)
	in := v.signingInput()

	// The amino-JSON sign doc must be byte-identical to the cosmos-sdk's.
	sb, err := cosmosMultisigSignBytes(in)
	if err != nil {
		t.Fatalf("cosmosMultisigSignBytes: %v", err)
	}
	if string(sb) != v.SignDocJSON {
		t.Fatalf("sign doc mismatch:\n got  %s\n want %s", sb, v.SignDocJSON)
	}

	for _, idx := range v.SignerIndices {
		w, err := FromPrivateKeyBytes(scalarPrivKey(byte(idx)+1), Secp256k1)
		if err != nil {
			t.Fatalf("FromPrivateKeyBytes: %v", err)
		}
		sig, err := w.SignCosmosMultisigPartial(ATOM, 0, in)
		w.Destroy()
		if err != nil {
			t.Fatalf("SignCosmosMultisigPartial(%d): %v", idx, err)
		}
		want := v.PartialSigsHex[itoa(idx)]
		if got := hex.EncodeToString(sig); got != want {
			t.Fatalf("partial sig %d mismatch:\n got  %s\n want %s", idx, got, want)
		}
	}
}

// itoa avoids importing strconv for two digits.
func itoa(i int) string { return string(rune('0' + i)) }

func TestCombineCosmosMultisigVector(t *testing.T) {
	v := loadCosmosMultisigVector(t)
	pubs := v.pubkeys(t)
	in := v.signingInput()

	sigs := map[int][]byte{}
	for _, idx := range v.SignerIndices {
		b, err := hex.DecodeString(v.PartialSigsHex[itoa(idx)])
		if err != nil {
			t.Fatalf("decode sig %d: %v", idx, err)
		}
		sigs[idx] = b
	}
	out, err := CombineCosmosMultisig(v.Threshold, pubs, in, sigs)
	if err != nil {
		t.Fatalf("CombineCosmosMultisig: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(out.GetEncoded()); got != v.TxRawBase64 {
		t.Fatalf("tx_raw mismatch:\n got  %s\n want %s", got, v.TxRawBase64)
	}
	if out.GetTxBytes() != v.TxRawBase64 {
		t.Fatalf("tx_bytes = %s, want %s", out.GetTxBytes(), v.TxRawBase64)
	}
	if out.GetTxId() != v.TxIDHex {
		t.Fatalf("tx_id = %s, want %s", out.GetTxId(), v.TxIDHex)
	}
}

func TestCosmosMultisigErrors(t *testing.T) {
	v := loadCosmosMultisigVector(t)
	pubs := v.pubkeys(t)
	in := v.signingInput()

	if _, err := CosmosMultisigAddress("cosmos", 0, pubs); !errors.Is(err, ErrTxInput) {
		t.Errorf("threshold 0: %v, want ErrTxInput", err)
	}
	if _, err := CosmosMultisigAddress("cosmos", 4, pubs); !errors.Is(err, ErrTxInput) {
		t.Errorf("threshold > n: %v, want ErrTxInput", err)
	}
	if _, err := CosmosMultisigAddress("cosmos", 2, [][]byte{pubs[0], pubs[1][:20], pubs[2]}); !errors.Is(err, ErrTxInput) {
		t.Errorf("bad pubkey: %v, want ErrTxInput", err)
	}

	// Partial signing restricted to standard (non-Ethermint) Cosmos chains.
	w, err := FromPrivateKeyBytes(scalarPrivKey(1), Secp256k1)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()
	if _, err := w.SignCosmosMultisigPartial(EVMOS, 0, in); !errors.Is(err, ErrTxUnsupported) {
		t.Errorf("EVMOS partial: %v, want ErrTxUnsupported", err)
	}
	if _, err := w.SignCosmosMultisigPartial(BTC, 0, in); !errors.Is(err, ErrTxUnsupported) {
		t.Errorf("BTC partial: %v, want ErrTxUnsupported", err)
	}

	// Combine guards.
	good, err := w.SignCosmosMultisigPartial(ATOM, 0, in)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	if _, err := CombineCosmosMultisig(2, pubs, in, map[int][]byte{0: good}); !errors.Is(err, ErrTxInput) {
		t.Errorf("insufficient sigs: %v, want ErrTxInput", err)
	}
	if _, err := CombineCosmosMultisig(2, pubs, in, map[int][]byte{0: good, 5: good}); !errors.Is(err, ErrTxInput) {
		t.Errorf("index out of range: %v, want ErrTxInput", err)
	}
	bad := make([]byte, 64)
	if _, err := CombineCosmosMultisig(2, pubs, in, map[int][]byte{0: good, 1: bad}); !errors.Is(err, ErrTxInput) {
		t.Errorf("invalid partial: %v, want ErrTxInput", err)
	}
}
