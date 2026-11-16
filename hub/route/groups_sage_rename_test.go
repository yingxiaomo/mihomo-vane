package route

import (
	"encoding/json"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSageRenamedRouteUsesRealGroup(t *testing.T) {
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	defer tunnel.UpdateProxies(oldProxies, oldProviders)
	home := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	defer C.SetHomeDir(home)
	direct := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "DIRECT"}))
	group, err := outboundgroup.ParseProxyGroup(map[string]any{"name": "rename", "type": "sage", "proxies": []string{"DIRECT"}, "exploration": true, "collect-events": true}, map[string]C.Proxy{"DIRECT": direct, "COMPATIBLE": direct}, map[string]P.ProxyProvider{}, nil, nil)
	require.NoError(t, err)
	defer group.Close()
	tunnel.UpdateProxies(map[string]C.Proxy{"rename": adapter.NewProxy(group)}, oldProviders)
	router := groupRouter()
	for _, tc := range []struct {
		path string
		code int
	}{{"/rename/sage", http.StatusOK}, {"/rename/adaptive", http.StatusNotFound}} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		require.Equal(t, tc.code, rec.Code)
		if tc.code == http.StatusOK {
			var snap outboundgroup.SageDiagnosticsSnapshot
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &snap))
			require.Equal(t, "rename", snap.Group)
			require.True(t, snap.Config.ExplorationEnabled)
			require.False(t, snap.Config.PriorEnabled)
			require.False(t, snap.Config.GrayFailureObservationEnabled)
		}
	}
}
