package route

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

type vaneDiagnosticsRouteAdapter struct {
	C.ProxyAdapter
	snapshot outboundgroup.VaneDiagnosticsSnapshot
}

func (a *vaneDiagnosticsRouteAdapter) VaneDiagnostics() outboundgroup.VaneDiagnosticsSnapshot {
	return a.snapshot
}

func TestGroupVaneDiagnosticsRoute(t *testing.T) {
	oldProxies := tunnel.Proxies()
	oldProviders := tunnel.Providers()
	defer tunnel.UpdateProxies(oldProxies, oldProviders)

	expected := outboundgroup.VaneDiagnosticsSnapshot{
		SchemaVersion:            outboundgroup.VaneDiagnosticsSchemaVersion,
		Group:                    "vane",
		Since:                    time.Unix(1_700_000_000, 0).UTC(),
		UpdatedAt:                time.Unix(1_700_000_001, 0).UTC(),
		PlayerTelemetryAvailable: false,
		Counters: outboundgroup.VaneDiagnosticCounters{
			ReconnectCommitted: 3,
		},
		GrayFailure: outboundgroup.VaneDiagnosticGrayFailure{
			Enabled:      true,
			Scope:        "member-transport",
			CurrentLevel: "watch",
			Counters: outboundgroup.VaneDiagnosticGrayCounters{
				AttemptEligible: 20,
				AttemptFailed:   3,
			},
			Exclusions: outboundgroup.VaneDiagnosticGrayExclusions{
				Attempt: map[string]uint64{"neutral-outcome": 1},
				Close:   map[string]uint64{},
			},
		},
	}
	vaneProxy := adapter.NewProxy(&vaneDiagnosticsRouteAdapter{
		ProxyAdapter: outbound.NewDirectWithOption(outbound.DirectOption{Name: "vane"}),
		snapshot:     expected,
	})
	directProxy := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "direct"}))
	tunnel.UpdateProxies(map[string]C.Proxy{
		"vane":   vaneProxy,
		"direct": directProxy,
	}, oldProviders)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/vane/vane", nil)
	groupRouter().ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var actual outboundgroup.VaneDiagnosticsSnapshot
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &actual))
	require.Equal(t, expected, actual)

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/direct/vane", nil)
	groupRouter().ServeHTTP(recorder, request)
	require.Equal(t, http.StatusNotFound, recorder.Code)
}
