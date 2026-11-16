package executor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

const sageRestartModeEnv = "MIHOMO_SAGE_RESTART_MODE"
const sageRestartHomeEnv = "MIHOMO_SAGE_RESTART_HOME"

func sageRestartConfig(group string) []byte {
	return []byte(fmt.Sprintf(`
port: 0
socks-port: 0
mixed-port: 0
redir-port: 0
tproxy-port: 0
log-level: silent
profile:
  store-selected: false
  store-fake-ip: false
dns:
  enable: false
proxies:
  - name: alpha
    type: direct
  - name: beta
    type: direct
proxy-groups:
  - name: %s
    type: sage
    proxies: [alpha, beta]
    target-cooldown: 3600
rules:
  - MATCH,%s
`, group, group))
}

func applySageRestartConfig(t *testing.T, group string) {
	t.Helper()
	cfg, err := ParseWithBytes(sageRestartConfig(group))
	require.NoError(t, err)
	ApplyConfig(cfg, true)
}

func runSageRestartChild(t *testing.T, mode, home string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestSageLearningSurvivesRealProcessRestart$")
	cmd.Env = append(os.Environ(), sageRestartModeEnv+"="+mode, sageRestartHomeEnv+"="+home)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "child mode %s failed:\n%s", mode, output)
}

func TestSageLearningSurvivesRealProcessRestart(t *testing.T) {
	if mode := os.Getenv(sageRestartModeEnv); mode != "" {
		home := os.Getenv(sageRestartHomeEnv)
		require.NotEmpty(t, home)
		require.NoError(t, os.MkdirAll(home, 0o755))
		C.SetHomeDir(home)
		if mode == "failed-parse-capacity" {
			for i := 0; i < 270; i++ {
				group := fmt.Sprintf("FAILED-%03d", i)
				invalid := strings.Replace(string(sageRestartConfig(group)), "MATCH,"+group, "NOT-A-VALID-RULE", 1)
				_, err := ParseWithBytes([]byte(invalid))
				require.Error(t, err)
			}
			group := "AFTER-FAILED-PARSES"
			applySageRestartConfig(t, group)
			proxy := tunnel.Proxies()[group]
			require.NotNil(t, proxy)
			sage := proxy.Adapter().(*outboundgroup.Sage)
			require.True(t, sage.SageDiagnostics().LearningPersistence.Available, "failed parses must not consume the durable owner registry")
			Shutdown()
			return
		}
		groupName := "AUTO"
		if mode == "cold" {
			groupName = "COLD"
		}
		applySageRestartConfig(t, groupName)

		proxy := tunnel.Proxies()[groupName]
		require.NotNil(t, proxy)
		switch mode {
		case "write":
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			address := reservation.Addr().String()
			port := uint16(reservation.Addr().(*net.TCPAddr).Port)
			require.NoError(t, reservation.Close())
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: port}
			_, err = proxy.DialContext(context.Background(), metadata)
			require.Error(t, err, "alphabetically first alpha must provide the failure evidence")

			listener, err := net.Listen("tcp4", address)
			require.NoError(t, err)
			defer listener.Close()
			accepted := make(chan struct{})
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					_ = conn.Close()
				}
				close(accepted)
			}()
			conn, err := proxy.DialContext(context.Background(), metadata)
			require.NoError(t, err, "target cooldown must route the second attempt through beta")
			require.NoError(t, conn.Close())
			select {
			case <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("direct beta connection was not accepted")
			}
			Shutdown()
		case "read":
			diagnostics, marshalErr := proxy.MarshalJSON()
			require.NoError(t, marshalErr)
			sage := proxy.Adapter().(*outboundgroup.Sage)
			learning := sage.SageDiagnostics().LearningPersistence
			require.Greater(t, learning.RestoredNodes, 0, "the child must load durable node evidence before selection")
			require.Equal(t, "beta", proxy.Unwrap(nil, false).Name(), "fresh process must restore evidence before the first selection; diagnostics=%s persistence=%+v", diagnostics, learning)
			Shutdown()
		case "cold":
			require.Equal(t, "alpha", proxy.Unwrap(nil, false).Name(), "a different group key must not inherit AUTO evidence")
			Shutdown()
		default:
			t.Fatalf("unknown restart child mode %q", mode)
		}
		return
	}

	home := filepath.Join(t.TempDir(), "profile")
	runSageRestartChild(t, "write", home)
	require.FileExists(t, filepath.Join(home, "cache.db"))
	runSageRestartChild(t, "read", home)
	runSageRestartChild(t, "cold", home)
	runSageRestartChild(t, "failed-parse-capacity", home)
}
