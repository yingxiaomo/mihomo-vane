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

type sageDiagnosticsRouteAdapter struct {
	C.ProxyAdapter
	snapshot outboundgroup.SageDiagnosticsSnapshot
}

func (a *sageDiagnosticsRouteAdapter) SageDiagnostics() outboundgroup.SageDiagnosticsSnapshot {
	return a.snapshot
}

func TestGroupSageDiagnosticsRoute(t *testing.T) {
	oldProxies := tunnel.Proxies()
	oldProviders := tunnel.Providers()
	defer tunnel.UpdateProxies(oldProxies, oldProviders)

	expected := outboundgroup.SageDiagnosticsSnapshot{
		SchemaVersion:            outboundgroup.SageDiagnosticsSchemaVersion,
		Group:                    "sage",
		Since:                    time.Unix(1_700_000_000, 0).UTC(),
		UpdatedAt:                time.Unix(1_700_000_001, 0).UTC(),
		PlayerTelemetryAvailable: false,
		Counters: outboundgroup.SageDiagnosticCounters{
			ReconnectCommitted: 3,
		},
		GrayFailure: outboundgroup.SageDiagnosticGrayFailure{
			Enabled:      true,
			Scope:        "member-transport",
			CurrentLevel: "watch",
			Counters: outboundgroup.SageDiagnosticGrayCounters{
				AttemptEligible: 20,
				AttemptFailed:   3,
			},
			Exclusions: outboundgroup.SageDiagnosticGrayExclusions{
				Attempt: map[string]uint64{"neutral-outcome": 1},
				Close:   map[string]uint64{},
			},
		},
	}
	sageProxy := adapter.NewProxy(&sageDiagnosticsRouteAdapter{
		ProxyAdapter: outbound.NewDirectWithOption(outbound.DirectOption{Name: "sage"}),
		snapshot:     expected,
	})
	directProxy := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "direct"}))
	tunnel.UpdateProxies(map[string]C.Proxy{
		"sage":   sageProxy,
		"direct": directProxy,
	}, oldProviders)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sage/sage", nil)
	groupRouter().ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var actual outboundgroup.SageDiagnosticsSnapshot
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &actual))
	require.Equal(t, expected, actual)

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/direct/sage", nil)
	groupRouter().ServeHTTP(recorder, request)
	require.Equal(t, http.StatusNotFound, recorder.Code)
}
