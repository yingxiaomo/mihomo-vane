package outboundgroup

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// vaneBandwidth is a config value that accepts either a plain byte count
// (10000000, backward compatible) or a decimal-suffixed string ("10M", "1.5M",
// "500K", "1G"). The suffixes are decimal: 1K = 1000, 1M = 1000*1000,
// 1G = 1000^3 — "10M" is exactly 10000000, matching the plain form.
type vaneBandwidth int64

// UnmarshalText implements encoding.TextUnmarshaler. The structure decoder
// feeds it the config value rendered as a string (ints become decimal strings,
// floats become Go float formatting — ParseFloat handles both).
func (b *vaneBandwidth) UnmarshalText(text []byte) error {
	parsed, err := parseVaneBandwidth(string(text))
	if err != nil {
		return err
	}
	*b = vaneBandwidth(parsed)
	return nil
}

// parseVaneBandwidth parses a byte count with optional decimal suffix
// (K/M/G, case-insensitive), an optional decimal fraction ("1.5M"), or a bare
// byte count / float rendering of one ("10000000", "1.500000E+09").
func parseVaneBandwidth(text string) (float64, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, fmt.Errorf("empty bandwidth value")
	}
	multiplier := 1.0
	upper := strings.ToUpper(trimmed)
	if last := upper[len(upper)-1]; last == 'K' || last == 'M' || last == 'G' {
		switch last {
		case 'K':
			multiplier = 1_000
		case 'M':
			multiplier = 1_000 * 1000
		case 'G':
			multiplier = 1000 * 1000 * 1000
		}
		trimmed = strings.TrimSpace(upper[:len(upper)-1])
	}
	number, err := strconv.ParseFloat(trimmed, 64)
	// P2 (audit 2026-11-22): ParseFloat accepts "NaN"/"Inf" with err == nil
	// and neither is < 0; the float→int64 conversion downstream is
	// architecture-dependent (amd64 clamps to MinInt64, arm64 saturates NaN
	// to 0 — a silent misconfiguration). Reject them and any finite value
	// whose product overflows int64.
	if err != nil || number < 0 || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, fmt.Errorf("invalid bandwidth value %q: must be a non-negative number with an optional K/M/G suffix", text)
	}
	bits := number * multiplier
	// math.MaxInt64 rounds to 2^63 in float64 context, so the previous
	// `bits > math.MaxInt64` never fired: values from 2^63-1024 up parsed to
	// exactly 2^63 and amd64's int64 conversion made them negative.
	if math.IsNaN(bits) || math.IsInf(bits, 0) || bits >= 9223372036854775808.0 {
		return 0, fmt.Errorf("bandwidth value %q overflows the maximum", text)
	}
	return bits, nil
}
