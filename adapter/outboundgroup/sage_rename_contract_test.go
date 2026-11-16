package outboundgroup

import (
	"encoding/json"
	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/require"
	"testing"
)

// Literal public-contract test: must fail on the pre-rename implementation.
func TestSageRenamePublicContract(t *testing.T) {
	direct := A.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "DIRECT"}))
	proxies := map[string]C.Proxy{"DIRECT": direct, "COMPATIBLE": direct}
	for _, tc := range []struct {
		name  string
		valid bool
	}{{"sage", true}, {"adap" + "tive", false}} {
		t.Run(tc.name, func(t *testing.T) {
			group, err := ParseProxyGroup(map[string]any{"name": "rename-contract", "type": tc.name, "proxies": []string{"DIRECT"}}, proxies, map[string]P.ProxyProvider{}, nil, nil)
			if !tc.valid {
				if group != nil {
					_ = group.Close()
				}
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			defer group.Close()
			require.Equal(t, "Sage", group.Type().String())
			require.Equal(t, C.AdapterType(37), group.Type())
			payload, err := group.MarshalJSON()
			require.NoError(t, err)
			var document map[string]any
			require.NoError(t, json.Unmarshal(payload, &document))
			require.Equal(t, "Sage", document["type"])
		})
	}
}
