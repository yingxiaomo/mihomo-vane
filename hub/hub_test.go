//go:build integration

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
)

func TestParseReturnsVaneActivationError(t *testing.T) {
	const childEnv = "MIHOMO_TEST_VANE_PARSE_ERROR"
	if os.Getenv(childEnv) == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestParseReturnsVaneActivationError$")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "child failed:\n%s", output)
		return
	}

	C.SetHomeDir(t.TempDir())
	cache := cachefile.Cache()
	t.Cleanup(func() { require.NoError(t, cache.Close()) })
	blocked := filepath.Join(C.Path.HomeDir(), "collector-file")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))
	quoted, err := json.Marshal(blocked)
	require.NoError(t, err)
	old := adapter.NewProxy(outbound.NewReject())
	before := map[string]C.Proxy{"OLD": old}
	tunnel.UpdateProxies(before, map[string]P.ProxyProvider{})
	beforeLogLevel := log.Level()

	err = Parse([]byte(fmt.Sprintf(`port: 0
socks-port: 0
mixed-port: 0
log-level: error
profile: {store-selected: false, store-fake-ip: false}
dns: {enable: false}
proxy-groups:
  - name: NEW
    type: vane
    proxies: [REJECT]
    collect-events: true
    collector-dir: %s
rules:
  - MATCH,NEW
`, quoted)))
	require.ErrorContains(t, err, "prepare vane learning state")
	require.ErrorContains(t, err, "create collector directory")
	var pathError *os.PathError
	require.True(t, errors.As(err, &pathError), "application must preserve the underlying filesystem error")
	require.Equal(t, before, tunnel.Proxies(), "failed startup/reload must preserve the active graph")
	require.Equal(t, beforeLogLevel, log.Level(), "failed preparation must not alter the active log level")
}
