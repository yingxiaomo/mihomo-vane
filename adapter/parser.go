package adapter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"reflect"
	"sort"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

func ParseProxy(mapping map[string]any, options ...ProxyOption) (C.Proxy, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	opt := applyProxyOptions(options...)
	basicOption := outbound.BasicOption{
		DialerForAPI: opt.DialerForAPI,
		TunnelForAPI: opt.TunnelForAPI,
		ProviderName: opt.ProviderName,
	}

	var (
		proxy outbound.ProxyAdapter
		err   error
	)
	switch proxyType {
	case "ss":
		ssOption := &outbound.ShadowSocksOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	case "hysteria":
		hyOption := &outbound.HysteriaOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria(*hyOption)
	case "hysteria2":
		hyOption := &outbound.Hysteria2Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria2(*hyOption)
	case "wireguard":
		wgOption := &outbound.WireGuardOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, wgOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewWireGuard(*wgOption)
	case "tuic":
		tuicOption := &outbound.TuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTuic(*tuicOption)
	case "shadowquic":
		shadowQuicOption := &outbound.ShadowQuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, shadowQuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowQuic(*shadowQuicOption)
	case "gost-relay":
		relayOption := &outbound.GostRelayOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, relayOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewGostRelay(*relayOption)
	case "direct":
		directOption := &outbound.DirectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, directOption)
		if err != nil {
			break
		}
		proxy = outbound.NewDirectWithOption(*directOption)
	case "dns":
		dnsOptions := &outbound.DnsOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, dnsOptions)
		if err != nil {
			break
		}
		proxy = outbound.NewDnsWithOption(*dnsOptions)
	case "reject":
		rejectOption := &outbound.RejectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rejectOption)
		if err != nil {
			break
		}
		proxy = outbound.NewRejectWithOption(*rejectOption)
	case "rematch":
		rematchOption := &outbound.RematchOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rematchOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewRematch(*rematchOption)
	case "ssh":
		sshOption := &outbound.SshOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sshOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSsh(*sshOption)
	case "mieru":
		mieruOption := &outbound.MieruOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, mieruOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMieru(*mieruOption)
	case "anytls":
		anytlsOption := &outbound.AnyTLSOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, anytlsOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewAnyTLS(*anytlsOption)
	case "sudoku":
		sudokuOption := &outbound.SudokuOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sudokuOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSudoku(*sudokuOption)
	case "masque":
		masqueOption := &outbound.MasqueOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, masqueOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMasque(*masqueOption)
	case "trusttunnel":
		trustTunnelOption := &outbound.TrustTunnelOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trustTunnelOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrustTunnel(*trustTunnelOption)
	case "openvpn":
		openVPNOption := &outbound.OpenVPNOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, openVPNOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewOpenVPN(*openVPNOption)
	case "tailscale":
		tailscaleOption := &outbound.TailscaleOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tailscaleOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTailscale(*tailscaleOption)
	case "zerotier":
		zeroTierOption := &outbound.ZeroTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, zeroTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewZeroTier(*zeroTierOption)
	case "easytier":
		easyTierOption := &outbound.EasyTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, easyTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewEasyTier(*easyTierOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	if err != nil {
		return nil, err
	}

	if muxMapping, muxExist := mapping["smux"].(map[string]any); muxExist {
		muxOption := &outbound.SingMuxOption{}
		err = decoder.Decode(muxMapping, muxOption)
		if err != nil {
			return nil, err
		}
		if muxOption.Enabled {
			proxy, err = outbound.NewSingMux(*muxOption, proxy)
			if err != nil {
				return nil, err
			}
		}
	}

	proxy = outbound.NewAutoCloseProxyAdapter(proxy)
	parsed := NewProxy(proxy)
	// Persistent identity is derived exclusively from the normalized raw mapping
	// and provider scope. Runtime API wiring is not part of the proxy entity and
	// must not disable identity generation: production config parsing always
	// supplies TunnelForAPI.
	identity, err := persistentProxyIdentity(mapping, opt.ProviderName)
	if err != nil {
		return nil, fmt.Errorf("derive proxy identity: %w", err)
	}
	parsed.persistentIdentity = "proxy-config-v1:" + identity
	return parsed, nil
}

func writeProxyIdentityBytes(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

func writeCanonicalProxyIdentity(h hash.Hash, value reflect.Value) error {
	if !value.IsValid() || ((value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) && value.IsNil()) {
		_, _ = h.Write([]byte{'n'})
		return nil
	}
	if value.Kind() == reflect.Interface {
		return writeCanonicalProxyIdentity(h, value.Elem())
	}
	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			_, _ = h.Write([]byte("b1"))
		} else {
			_, _ = h.Write([]byte("b0"))
		}
	case reflect.String:
		_, _ = h.Write([]byte{'s'})
		writeProxyIdentityBytes(h, []byte(value.String()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, _ = h.Write([]byte{'i'})
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(value.Int()))
		_, _ = h.Write(encoded[:])
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		_, _ = h.Write([]byte{'u'})
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value.Uint())
		_, _ = h.Write(encoded[:])
	case reflect.Float32:
		_, _ = h.Write([]byte{'f', '4'})
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], math.Float32bits(float32(value.Float())))
		_, _ = h.Write(encoded[:])
	case reflect.Float64:
		_, _ = h.Write([]byte{'f', '8'})
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], math.Float64bits(value.Float()))
		_, _ = h.Write(encoded[:])
	case reflect.Slice, reflect.Array:
		_, _ = h.Write([]byte{'a'})
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(value.Len()))
		_, _ = h.Write(size[:])
		for i := 0; i < value.Len(); i++ {
			if err := writeCanonicalProxyIdentity(h, value.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("unsupported map key type %s", value.Type().Key())
		}
		_, _ = h.Write([]byte{'m'})
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(keys)))
		_, _ = h.Write(size[:])
		for _, key := range keys {
			writeProxyIdentityBytes(h, []byte(key.String()))
			if err := writeCanonicalProxyIdentity(h, value.MapIndex(key)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported value type %s", value.Type())
	}
	return nil
}

func persistentProxyIdentity(mapping map[string]any, providerName string) (string, error) {
	h := sha256.New()
	_, _ = h.Write([]byte("proxy-config-v1\x00"))
	if err := writeCanonicalProxyIdentity(h, reflect.ValueOf(mapping)); err != nil {
		return "", err
	}
	writeProxyIdentityBytes(h, []byte(providerName))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

type proxyOption struct {
	DialerForAPI C.Dialer
	TunnelForAPI C.Tunnel
	ProviderName string
}

func applyProxyOptions(options ...ProxyOption) proxyOption {
	opt := proxyOption{}
	for _, o := range options {
		o(&opt)
	}
	return opt
}

type ProxyOption func(opt *proxyOption)

func WithDialerForAPI(dialer C.Dialer) ProxyOption {
	return func(opt *proxyOption) {
		opt.DialerForAPI = dialer
	}
}

func WithTunnelForAPI(tunnel C.Tunnel) ProxyOption {
	return func(opt *proxyOption) {
		opt.TunnelForAPI = tunnel
	}
}

func WithProviderName(name string) ProxyOption {
	return func(opt *proxyOption) {
		opt.ProviderName = name
	}
}
