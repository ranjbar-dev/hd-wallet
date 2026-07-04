package hdwallet

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Sentinel errors for amount parsing.
var (
	// ErrNegativeAmount is returned by ParseAmount and ParseUnits when the input
	// string represents a negative value. Wallet amounts are non-negative by
	// definition, so negative inputs are rejected rather than silently accepted.
	ErrNegativeAmount = errors.New("hdwallet: amount must not be negative")

	// ErrInvalidAmount is returned by ParseAmount and ParseUnits when the input
	// string is not a valid unsigned decimal number. Triggers include an empty
	// string, multiple decimal points, non-numeric characters, or more fractional
	// digits than the declared precision (extra precision is rejected rather than
	// silently truncated — a wrong value means permanently lost funds).
	ErrInvalidAmount = errors.New("hdwallet: invalid amount string")
)

// NativeDecimals returns the number of fractional digits in the coin's native
// base unit (e.g. 8 for BTC/satoshis, 18 for ETH/wei, 6 for ATOM/uatom).
//
// The second return value reports whether chain is a registered coin; an
// unregistered chain returns (0, false). This is a thin convenience wrapper
// over CoinInfo for callers that only need the decimal count.
func NativeDecimals(chain Chain) (uint8, bool) {
	c, ok := coins[chain]
	if !ok {
		return 0, false
	}
	return c.Decimals, true
}

// FormatAmount converts a raw integer amount (in the coin's native smallest
// unit) to a human-readable decimal string using the decimal count registered
// for chain. It returns ErrUnsupportedCoin for an unknown chain.
//
// This is the native-coin helper. For ERC-20, SPL, or TRC-20 tokens whose
// decimal count comes from the token contract, use FormatUnits directly.
//
// Examples:
//
//	FormatAmount(BTC, big.NewInt(100_000_000)) // "1"   (1 BTC = 1e8 satoshis)
//	FormatAmount(ETH, big.NewInt(1_500_000_000_000_000_000)) // "1.5"
func FormatAmount(chain Chain, raw *big.Int) (string, error) {
	dec, ok := NativeDecimals(chain)
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCoin, chain)
	}
	return FormatUnits(raw, dec), nil
}

// ParseAmount parses a human-readable unsigned decimal string into its raw
// integer representation using the decimal count registered for chain.
// Returns ErrUnsupportedCoin for an unknown chain, ErrNegativeAmount for a
// negative input, and ErrInvalidAmount for a malformed string.
//
// This is the native-coin helper. For ERC-20, SPL, or TRC-20 tokens whose
// decimal count comes from the token contract, use ParseUnits directly.
//
// Examples:
//
//	ParseAmount(BTC, "0.5")  // big.Int: 50_000_000
//	ParseAmount(ETH, "1.5")  // big.Int: 1_500_000_000_000_000_000
func ParseAmount(chain Chain, human string) (*big.Int, error) {
	dec, ok := NativeDecimals(chain)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, chain)
	}
	return ParseUnits(human, dec)
}

// FormatUnits converts a raw integer amount to a human-readable decimal string
// with the given decimal precision. It is the coin-agnostic primitive used by
// FormatAmount, and is the correct helper for ERC-20, SPL, and TRC-20 tokens
// where the decimal count is provided by the token contract's metadata rather
// than the native coin registry.
//
// Trailing fractional zeros are stripped ("1.500" → "1.5"). A nil raw is
// treated as zero. Negative raw values are formatted with a leading "-".
//
// Examples (decimals=18):
//
//	FormatUnits(big.NewInt(0), 18)                              // "0"
//	FormatUnits(big.NewInt(1_000_000_000_000_000_000), 18)      // "1"
//	FormatUnits(big.NewInt(1_500_000_000_000_000_000), 18)      // "1.5"
//	FormatUnits(big.NewInt(1), 18)                              // "0.000000000000000001"
func FormatUnits(raw *big.Int, decimals uint8) string {
	if raw == nil {
		raw = new(big.Int)
	}
	if decimals == 0 {
		return raw.String()
	}

	// Work with the absolute value; restore the sign at the end.
	negative := raw.Sign() < 0
	abs := new(big.Int).Abs(raw)

	divisor := amountPow10(decimals)
	quot := new(big.Int)
	rem := new(big.Int)
	quot.DivMod(abs, divisor, rem)

	intStr := quot.String()
	if negative {
		intStr = "-" + intStr
	}
	if rem.Sign() == 0 {
		return intStr
	}

	// Left-pad the remainder to exactly decimals digits, then trim trailing zeros.
	remStr := rem.String()
	if pad := int(decimals) - len(remStr); pad > 0 {
		remStr = strings.Repeat("0", pad) + remStr
	}
	return intStr + "." + strings.TrimRight(remStr, "0")
}

// ParseUnits parses a human-readable unsigned decimal string into its raw
// integer representation with the given decimal precision. It is the
// coin-agnostic primitive used by ParseAmount, and is the correct helper for
// ERC-20, SPL, and TRC-20 tokens where the decimal count is provided by the
// token contract's metadata.
//
// Parsing rules:
//   - Negative values are rejected with ErrNegativeAmount.
//   - The fractional part must not exceed decimals digits; extra precision is
//     rejected with ErrInvalidAmount (no silent truncation — a wrong value means
//     lost funds).
//   - Non-numeric characters and multiple decimal points return ErrInvalidAmount.
//   - A leading dot (e.g. ".5") is accepted and treated as "0.5".
//
// Examples (decimals=18):
//
//	ParseUnits("1",   18) // 1_000_000_000_000_000_000
//	ParseUnits("1.5", 18) // 1_500_000_000_000_000_000
//	ParseUnits("0",   18) // 0
func ParseUnits(human string, decimals uint8) (*big.Int, error) {
	if len(human) == 0 {
		return nil, fmt.Errorf("%w: empty string", ErrInvalidAmount)
	}
	if human[0] == '-' {
		return nil, ErrNegativeAmount
	}

	dot := strings.IndexByte(human, '.')
	var intPart, fracPart string
	if dot < 0 {
		intPart = human
	} else {
		intPart = human[:dot]
		fracPart = human[dot+1:]
		if strings.IndexByte(fracPart, '.') >= 0 {
			return nil, fmt.Errorf("%w: multiple decimal points in %q", ErrInvalidAmount, human)
		}
	}

	if intPart == "" {
		intPart = "0"
	}

	if !amountAllDigits(intPart) {
		return nil, fmt.Errorf("%w: non-numeric characters in %q", ErrInvalidAmount, human)
	}
	if fracPart != "" && !amountAllDigits(fracPart) {
		return nil, fmt.Errorf("%w: non-numeric characters in %q", ErrInvalidAmount, human)
	}
	if len(fracPart) > int(decimals) {
		return nil, fmt.Errorf(
			"%w: %d fractional digits in %q exceed precision %d",
			ErrInvalidAmount, len(fracPart), human, decimals,
		)
	}

	divisor := amountPow10(decimals)
	intVal, ok := new(big.Int).SetString(intPart, 10)
	if !ok {
		// SetString fails only for genuinely malformed strings; amountAllDigits
		// above already ensured all digits, so this branch is unreachable in
		// practice but kept for safety.
		return nil, fmt.Errorf("%w: cannot parse integer part of %q", ErrInvalidAmount, human)
	}
	result := new(big.Int).Mul(intVal, divisor)

	if fracPart != "" {
		// Right-pad the fractional part to exactly decimals digits before parsing.
		padded := fracPart + strings.Repeat("0", int(decimals)-len(fracPart))
		fracVal, ok := new(big.Int).SetString(padded, 10)
		if !ok {
			return nil, fmt.Errorf("%w: cannot parse fractional part of %q", ErrInvalidAmount, human)
		}
		result.Add(result, fracVal)
	}
	return result, nil
}

// amountPow10 returns 10^n as a new *big.Int.
func amountPow10(n uint8) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
}

// amountAllDigits reports whether s is non-empty and consists entirely of
// ASCII decimal digit characters ('0'–'9').
func amountAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
