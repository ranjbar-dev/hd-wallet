package hdwallet

import (
	"errors"
	"testing"
)

// Each (wallet, mint) → ATA triple below is taken from a Trust Wallet Core
// signing vector tied to an on-chain-confirmed Solana transaction
// (trustwallet/wallet-core rust/tw_tests/tests/chains/solana/solana_sign.rs).
// SRM mint: SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt
// USDT-like mint: 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU
func TestSolanaTokenAccountAddress(t *testing.T) {
	cases := []struct{ wallet, mint, want string }{
		{"B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt", "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP"},
		{"Eg5jqooyG6ySaXKbQUu4Lpvu2SqUPZrNkM4zXs9iUDLJ", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt", "ANVCrmRw7Ww7rTFfMbrjApSPXEEcZpBa6YEiBdf98pAf"},
		{"71e8mDsh3PR6gN64zL1HjwuxyKpgRXrPDUJT7XXojsVd", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt", "EF6L8yJT1SoRoDCkAZfSVmaweqMzfhxZiptKi7Tgj5XY"},
		{"3xJ3MoUVFPNFEHfWdtNFa8ajXUHsJPzXcBSWMKLd76ft", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt", "67BrwFYt7qUnbAcYBVx7sQ4jeD2KWN1ohP6bMikmmQV3"},
		{"3WUX9wASxyScbA7brDipioKfXS1XEYkQ4vo3Kej9bKei", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "BwTAyrCEdkjNyGSGVNSSGh6phn8KQaLN638Evj7PVQfJ"},
		{"B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "5sS5Z8GAdVHqZKRqEvpDauHvvLgbDveiyfi81uh25mrf"},
		{"3UVYmECPPMZSCqWKfENfuoTv51fTDTWicX9xmBD2euKe", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "93hbN3brRjZqRQTT9Xx6rAHVDFZFWD9ragFDXvDbTEjr"},
	}
	for _, c := range cases {
		got, err := SolanaTokenAccountAddress(c.wallet, c.mint)
		if err != nil {
			t.Fatalf("SolanaTokenAccountAddress(%s, %s): %v", c.wallet, c.mint, err)
		}
		if got != c.want {
			t.Errorf("ATA(%s, %s) = %s, want %s", c.wallet, c.mint, got, c.want)
		}
	}
}

func TestSolanaTokenAccountAddressErrors(t *testing.T) {
	// bad base58
	if _, err := SolanaTokenAccountAddress("not-base58-0OIl", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("bad wallet: err = %v, want ErrInvalidAddress", err)
	}
	// wrong length (decodes to <32 bytes)
	if _, err := SolanaTokenAccountAddress("abc", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("short wallet: err = %v, want ErrInvalidAddress", err)
	}
	if _, err := SolanaTokenAccountAddress("B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V", "abc"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("short mint: err = %v, want ErrInvalidAddress", err)
	}
}
