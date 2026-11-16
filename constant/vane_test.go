package constant

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdapterTypeValuesRemainStableWithVaneAppended(t *testing.T) {
	tests := []struct {
		name string
		got  AdapterType
		want AdapterType
	}{
		{"Direct", Direct, 0},
		{"Reject", Reject, 1},
		{"RejectDrop", RejectDrop, 2},
		{"Compatible", Compatible, 3},
		{"Pass", Pass, 4},
		{"PassRule", PassRule, 5},
		{"Rematch", Rematch, 6},
		{"Dns", Dns, 7},
		{"Relay", Relay, 8},
		{"Selector", Selector, 9},
		{"Fallback", Fallback, 10},
		{"URLTest", URLTest, 11},
		{"LoadBalance", LoadBalance, 12},
		{"Shadowsocks", Shadowsocks, 13},
		{"ShadowsocksR", ShadowsocksR, 14},
		{"Snell", Snell, 15},
		{"Socks5", Socks5, 16},
		{"Http", Http, 17},
		{"Vmess", Vmess, 18},
		{"Vless", Vless, 19},
		{"Trojan", Trojan, 20},
		{"Hysteria", Hysteria, 21},
		{"Hysteria2", Hysteria2, 22},
		{"WireGuard", WireGuard, 23},
		{"Tuic", Tuic, 24},
		{"Ssh", Ssh, 25},
		{"Mieru", Mieru, 26},
		{"AnyTLS", AnyTLS, 27},
		{"Sudoku", Sudoku, 28},
		{"Masque", Masque, 29},
		{"TrustTunnel", TrustTunnel, 30},
		{"ShadowQuic", ShadowQuic, 31},
		{"OpenVPN", OpenVPN, 32},
		{"Tailscale", Tailscale, 33},
		{"ZeroTier", ZeroTier, 34},
		{"EasyTier", EasyTier, 35},
		{"GostRelay", GostRelay, 36},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, test.got)
		})
	}
	require.Equal(t, AdapterType(37), Vane)
	require.Equal(t, "Vane", Vane.String())
}
