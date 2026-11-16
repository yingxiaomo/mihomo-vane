package tunnel

import (
	"fmt"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

func TestProxyPublicationAndReadersAreSynchronized(t *testing.T) {
	const iterations = 1000
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := 0; i < iterations; i++ {
			UpdateProxiesWithCommit(
				map[string]C.Proxy{fmt.Sprintf("proxy-%d", i): nil},
				map[string]P.ProxyProvider{},
				nil,
			)
		}
	}()
	go func() {
		defer wait.Done()
		for i := 0; i < iterations; i++ {
			snapshot := Proxies()
			snapshot["caller-owned"] = nil
			_ = Providers()
			_ = Tunnel.Proxies()
			_ = Tunnel.Providers()
		}
	}()
	wait.Wait()

	_, leaked := Proxies()["caller-owned"]
	require.False(t, leaked, "public getters must not expose the mutable published map")
}
