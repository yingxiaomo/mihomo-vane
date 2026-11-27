//go:build integration

package route

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
)

func TestVaneConfigApplyHTTP(t *testing.T) {
	const modeEnv = "MIHOMO_TEST_VANE_CONFIG_HTTP"
	if mode := os.Getenv(modeEnv); mode != "" {
		runVaneConfigApplyHTTP(t, mode)
		return
	}
	for _, mode := range []string{"collector-failure", "collector-success"} {
		t.Run(mode, func(t *testing.T) {
			// ApplyConfig changes process-wide listeners and logging; isolate each case.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestVaneConfigApplyHTTP$")
			cmd.Env = append(os.Environ(), modeEnv+"="+mode)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "child %s failed:\n%s", mode, output)
		})
	}
}

func runVaneConfigApplyHTTP(t *testing.T, mode string) {
	t.Helper()
	C.SetHomeDir(t.TempDir())
	cache := cachefile.Cache()
	t.Cleanup(func() { require.NoError(t, cache.Close()) })
	configBytes := func(group, directory string, collect bool) []byte {
		quoted, err := json.Marshal(directory)
		require.NoError(t, err)
		// REJECT is built in, so health checks cannot reach an external server.
		return []byte(fmt.Sprintf(`port: 0
socks-port: 0
mixed-port: 0
redir-port: 0
tproxy-port: 0
log-level: error
profile: {store-selected: false, store-fake-ip: false}
dns: {enable: false}
proxy-groups:
  - name: %s
    type: vane
    proxies: [REJECT]
    collect-events: %t
    collector-dir: %s
rules:
  - MATCH,%s
`, group, collect, quoted, group))
	}
	baseline, err := executor.ParseWithBytes(configBytes("OLD", "", false))
	require.NoError(t, err)
	tunnel.UpdateProxies(baseline.Proxies, baseline.Providers)
	beforeProxies, beforeProviders := tunnel.Proxies(), tunnel.Providers()
	beforeLogLevel := log.Level()

	directory := filepath.Join(C.Path.HomeDir(), "collector")
	if mode == "collector-failure" {
		require.NoError(t, os.WriteFile(directory, []byte("not a directory"), 0o600))
	}
	payload := configBytes("NEW", directory, true)
	// The failure must be in application, not YAML or Vane option validation.
	_, err = executor.ParseWithBytes(payload)
	require.NoError(t, err)
	body, err := json.Marshal(map[string]string{"payload": string(payload)})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	configRouter().ServeHTTP(recorder, request)

	if mode == "collector-failure" {
		require.Equal(t, http.StatusInternalServerError, recorder.Code, recorder.Body.String())
		var response struct {
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		require.Contains(t, response.Message, "prepare vane learning state")
		require.Contains(t, response.Message, "create collector directory")
		require.Equal(t, beforeProxies, tunnel.Proxies(), "failed application must preserve the old proxy graph")
		require.Equal(t, beforeProviders, tunnel.Providers(), "failed application must preserve the old providers")
		require.Equal(t, beforeLogLevel, log.Level(), "failed preparation must not change the active log level")
		return
	}

	require.Equal(t, http.StatusNoContent, recorder.Code, recorder.Body.String())
	require.Empty(t, recorder.Body.String())
	after := tunnel.Proxies()
	require.Contains(t, after, "NEW")
	require.NotContains(t, after, "OLD")
	group, ok := after["NEW"].Adapter().(*outboundgroup.Vane)
	require.True(t, ok)
	require.NoError(t, group.Close())
}
