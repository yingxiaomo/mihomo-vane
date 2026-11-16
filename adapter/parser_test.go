package adapter

import (
	"maps"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPersistentProxyIdentityTracksEffectiveConfiguration(t *testing.T) {
	base := map[string]any{
		"name":     "alpha",
		"type":     "socks5",
		"server":   "127.0.0.1",
		"port":     1080,
		"username": "user",
		"password": "secret-one",
		"smux": map[string]any{
			"enabled": false,
		},
	}
	identity := func(mapping map[string]any, provider string) string {
		t.Helper()
		proxy, err := ParseProxy(mapping, WithProviderName(provider))
		require.NoError(t, err)
		identified, ok := proxy.(interface{ PersistentIdentity() string })
		require.True(t, ok)
		return identified.PersistentIdentity()
	}

	first := identity(base, "provider-a")
	require.Contains(t, first, "proxy-config-v1:")

	reordered := map[string]any{
		"password": "secret-one",
		"username": "user",
		"port":     1080,
		"server":   "127.0.0.1",
		"type":     "socks5",
		"name":     "alpha",
		"smux":     map[string]any{"enabled": false},
	}
	require.Equal(t, first, identity(reordered, "provider-a"), "map insertion order must not affect identity")

	for name, mutate := range map[string]func(map[string]any){
		"server":   func(m map[string]any) { m["server"] = "127.0.0.2" },
		"port":     func(m map[string]any) { m["port"] = 1081 },
		"password": func(m map[string]any) { m["password"] = "secret-two" },
		"smux":     func(m map[string]any) { m["smux"] = map[string]any{"enabled": true} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := maps.Clone(base)
			mutate(changed)
			require.NotEqual(t, first, identity(changed, "provider-a"))
		})
	}
	require.NotEqual(t, first, identity(base, "provider-b"), "provider scope is part of identity")
}

func TestPersistentProxyIdentitySupportsNonFiniteYAMLNumbers(t *testing.T) {
	mapping := map[string]any{
		"name": "alpha", "type": "socks5", "server": "127.0.0.1", "port": 1080,
		"ignored-nan": math.NaN(),
	}
	first, err := ParseProxy(mapping)
	require.NoError(t, err)
	second, err := ParseProxy(mapping)
	require.NoError(t, err)
	firstIdentity := first.(interface{ PersistentIdentity() string }).PersistentIdentity()
	secondIdentity := second.(interface{ PersistentIdentity() string }).PersistentIdentity()
	require.Contains(t, firstIdentity, "proxy-config-v1:")
	require.Equal(t, firstIdentity, secondIdentity, "a successful production parse must never fall back to a random instance identity")
}
