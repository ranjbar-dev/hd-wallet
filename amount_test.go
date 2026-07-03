package hdwallet

import (
	"errors"
	"math/big"
	"testing"
)

// mustBigInt panics if s is not a valid base-10 integer literal; used only in
// table initialisation to make test cases readable.
func mustBigInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("mustBigInt: invalid literal: " + s)
	}
	return v
}

// --- FormatUnits ---

func TestFormatUnits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      *big.Int
		decimals uint8
		want     string
	}{
		// Zero
		{name: "zero/18dec", raw: big.NewInt(0), decimals: 18, want: "0"},
		{name: "zero/0dec", raw: big.NewInt(0), decimals: 0, want: "0"},
		{name: "nil/18dec", raw: nil, decimals: 18, want: "0"},

		// decimals=0 (integer coins)
		{name: "dec0/1", raw: big.NewInt(1), decimals: 0, want: "1"},
		{name: "dec0/large", raw: big.NewInt(9999), decimals: 0, want: "9999"},

		// Whole amounts (no fractional part)
		{name: "1 ETH", raw: mustBigInt("1000000000000000000"), decimals: 18, want: "1"},
		{name: "1 BTC", raw: big.NewInt(100_000_000), decimals: 8, want: "1"},
		{name: "1 ATOM", raw: big.NewInt(1_000_000), decimals: 6, want: "1"},

		// Trailing zeros stripped
		{name: "1.5 ETH no trailing zeros", raw: mustBigInt("1500000000000000000"), decimals: 18, want: "1.5"},
		{name: "1.50 BTC strips to 1.5", raw: big.NewInt(150_000_000), decimals: 8, want: "1.5"},
		{name: "1.10 ATOM strips to 1.1", raw: big.NewInt(1_100_000), decimals: 6, want: "1.1"},

		// Sub-unit precision (value < 1)
		{name: "1 wei", raw: big.NewInt(1), decimals: 18, want: "0.000000000000000001"},
		{name: "1 satoshi", raw: big.NewInt(1), decimals: 8, want: "0.00000001"},
		{name: "100 wei", raw: big.NewInt(100), decimals: 18, want: "0.0000000000000001"},

		// Values larger than uint64 max (≈1.8×10^19)
		// 100 ETH = 10^20 wei
		{
			name:     "100 ETH (>uint64)",
			raw:      mustBigInt("100000000000000000000"),
			decimals: 18,
			want:     "100",
		},
		// 1.000000000000000001 ETH — integer part + 1 wei residue, large int part
		{
			name:     "large int + small frac (>uint64)",
			raw:      mustBigInt("1000000000000000001000000000000000001"),
			decimals: 18,
			want:     "1000000000000000001.000000000000000001",
		},

		// Negative raw value — formatted with leading "-" (not rejected)
		{name: "negative 1 ETH", raw: mustBigInt("-1000000000000000000"), decimals: 18, want: "-1"},
		{name: "negative 1.5 BTC", raw: big.NewInt(-150_000_000), decimals: 8, want: "-1.5"},
		{name: "negative sub-unit", raw: big.NewInt(-1), decimals: 6, want: "-0.000001"},

		// 2 decimals
		{name: "2dec 1.23", raw: big.NewInt(123), decimals: 2, want: "1.23"},
		{name: "2dec 1.20 strips", raw: big.NewInt(120), decimals: 2, want: "1.2"},
		{name: "2dec 0.01", raw: big.NewInt(1), decimals: 2, want: "0.01"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FormatUnits(tc.raw, tc.decimals)
			if got != tc.want {
				t.Errorf("FormatUnits(%v, %d) = %q, want %q", tc.raw, tc.decimals, got, tc.want)
			}
		})
	}
}

// --- ParseUnits ---

func TestParseUnits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		human    string
		decimals uint8
		want     *big.Int // nil means error expected
		wantErr  error    // matched with errors.Is; nil = any error
	}{
		// Zero
		{name: "zero", human: "0", decimals: 18, want: big.NewInt(0)},
		{name: "zero.frac", human: "0.0", decimals: 18, want: big.NewInt(0)},

		// Whole amounts
		{name: "1 ETH", human: "1", decimals: 18, want: mustBigInt("1000000000000000000")},
		{name: "1 BTC", human: "1", decimals: 8, want: big.NewInt(100_000_000)},
		{name: "1 ATOM", human: "1", decimals: 6, want: big.NewInt(1_000_000)},

		// Fractional amounts
		{name: "1.5 ETH", human: "1.5", decimals: 18, want: mustBigInt("1500000000000000000")},
		{name: "0.5 BTC", human: "0.5", decimals: 8, want: big.NewInt(50_000_000)},
		{name: "0.000001 ATOM (1 uatom)", human: "0.000001", decimals: 6, want: big.NewInt(1)},

		// Sub-unit precision (full decimals)
		{name: "1 wei", human: "0.000000000000000001", decimals: 18, want: big.NewInt(1)},
		{name: "1 satoshi", human: "0.00000001", decimals: 8, want: big.NewInt(1)},

		// Leading dot accepted as 0.<frac>
		{name: "leading dot", human: ".5", decimals: 2, want: big.NewInt(50)},

		// Trailing dot accepted as whole number
		{name: "trailing dot", human: "1.", decimals: 6, want: big.NewInt(1_000_000)},

		// Values larger than uint64
		{
			name:     "100 ETH (>uint64)",
			human:    "100",
			decimals: 18,
			want:     mustBigInt("100000000000000000000"),
		},
		{
			name:     "very large with frac",
			human:    "1000000000000000001.000000000000000001",
			decimals: 18,
			want:     mustBigInt("1000000000000000001000000000000000001"),
		},

		// decimals=0 (integer coins)
		{name: "dec0 integer", human: "42", decimals: 0, want: big.NewInt(42)},
		{name: "dec0 zero", human: "0", decimals: 0, want: big.NewInt(0)},

		// --- Error cases ---

		// Negative rejection
		{name: "negative", human: "-1", decimals: 18, want: nil, wantErr: ErrNegativeAmount},
		{name: "negative frac", human: "-0.5", decimals: 18, want: nil, wantErr: ErrNegativeAmount},

		// Malformed inputs
		{name: "empty", human: "", decimals: 18, want: nil, wantErr: ErrInvalidAmount},
		{name: "letters", human: "abc", decimals: 18, want: nil, wantErr: ErrInvalidAmount},
		{name: "mixed", human: "1e18", decimals: 18, want: nil, wantErr: ErrInvalidAmount},
		{name: "double dot", human: "1.2.3", decimals: 18, want: nil, wantErr: ErrInvalidAmount},
		{name: "spaces", human: " 1", decimals: 18, want: nil, wantErr: ErrInvalidAmount},
		{name: "plus sign", human: "+1", decimals: 18, want: nil, wantErr: ErrInvalidAmount},

		// Extra fractional precision rejected (no silent truncation)
		{name: "too many frac digits", human: "1.1234567", decimals: 6, want: nil, wantErr: ErrInvalidAmount},
		{name: "dec0 with frac", human: "1.5", decimals: 0, want: nil, wantErr: ErrInvalidAmount},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseUnits(tc.human, tc.decimals)
			if tc.want == nil {
				// expect an error
				if err == nil {
					t.Fatalf("ParseUnits(%q, %d) = %v, want error", tc.human, tc.decimals, got)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("ParseUnits(%q, %d) error = %v, want wrapping %v", tc.human, tc.decimals, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUnits(%q, %d) unexpected error: %v", tc.human, tc.decimals, err)
			}
			if got.Cmp(tc.want) != 0 {
				t.Errorf("ParseUnits(%q, %d) = %v, want %v", tc.human, tc.decimals, got, tc.want)
			}
		})
	}
}

// TestParseFormatRoundTrip verifies that FormatUnits(ParseUnits(s, d), d) == s
// for a representative set of well-formed strings.
func TestParseFormatRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s string
		d uint8
	}{
		{"0", 18},
		{"1", 18},
		{"1.5", 18},
		{"0.000000000000000001", 18},
		{"100", 8},
		{"0.00000001", 8},
		{"1.23456789", 8},
		{"42", 0},
		{"1.23", 2},
		{"0.01", 2},
		{"1000000000000000001.000000000000000001", 18},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.s, func(t *testing.T) {
			t.Parallel()
			raw, err := ParseUnits(tc.s, tc.d)
			if err != nil {
				t.Fatalf("ParseUnits(%q, %d): %v", tc.s, tc.d, err)
			}
			got := FormatUnits(raw, tc.d)
			if got != tc.s {
				t.Errorf("round-trip(%q, %d): FormatUnits(ParseUnits) = %q", tc.s, tc.d, got)
			}
		})
	}
}

// --- FormatAmount / ParseAmount ---

func TestFormatAmount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		symbol  Symbol
		raw     *big.Int
		want    string
		wantErr error
	}{
		{ETH, mustBigInt("1000000000000000000"), "1", nil},
		{BTC, big.NewInt(100_000_000), "1", nil},
		{ATOM, big.NewInt(1_000_000), "1", nil},
		{ETH, big.NewInt(0), "0", nil},
		// Unknown symbol
		{Symbol("NOPE"), big.NewInt(1), "", ErrUnsupportedCoin},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.symbol), func(t *testing.T) {
			t.Parallel()
			got, err := FormatAmount(tc.symbol, tc.raw)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("FormatAmount(%s) error = %v, want %v", tc.symbol, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FormatAmount(%s) unexpected error: %v", tc.symbol, err)
			}
			if got != tc.want {
				t.Errorf("FormatAmount(%s, %v) = %q, want %q", tc.symbol, tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseAmount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		symbol  Symbol
		human   string
		want    *big.Int
		wantErr error
	}{
		{ETH, "1", mustBigInt("1000000000000000000"), nil},
		{BTC, "0.5", big.NewInt(50_000_000), nil},
		{ATOM, "1.5", big.NewInt(1_500_000), nil},
		{ETH, "0", big.NewInt(0), nil},
		// Unknown symbol
		{Symbol("NOPE"), "1", nil, ErrUnsupportedCoin},
		// Negative (ErrNegativeAmount propagated)
		{ETH, "-1", nil, ErrNegativeAmount},
		// Malformed
		{ETH, "abc", nil, ErrInvalidAmount},
		// Extra precision
		{ETH, "1.0000000000000000001", nil, ErrInvalidAmount},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.symbol)+"/"+tc.human, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAmount(tc.symbol, tc.human)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("ParseAmount(%s, %q) = %v, want error", tc.symbol, tc.human, got)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("ParseAmount(%s, %q) error = %v, want wrapping %v", tc.symbol, tc.human, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAmount(%s, %q) unexpected error: %v", tc.symbol, tc.human, err)
			}
			if got.Cmp(tc.want) != 0 {
				t.Errorf("ParseAmount(%s, %q) = %v, want %v", tc.symbol, tc.human, got, tc.want)
			}
		})
	}
}

// --- NativeDecimals ---

func TestNativeDecimals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		symbol Symbol
		want   uint8
		wantOK bool
	}{
		{BTC, 8, true},
		{ETH, 18, true},
		{ATOM, 6, true},
		{Symbol("NOPE"), 0, false}, // unknown
	}
	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.symbol), func(t *testing.T) {
			t.Parallel()
			got, ok := NativeDecimals(tc.symbol)
			if ok != tc.wantOK {
				t.Errorf("NativeDecimals(%s) ok = %v, want %v", tc.symbol, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("NativeDecimals(%s) = %d, want %d", tc.symbol, got, tc.want)
			}
		})
	}
}
