package provider

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestRegisterPrimaryHealthCheckTaskEnablesInterval(t *testing.T) {
	hc := NewHealthCheck(nil, C.DefaultTestURL, 0, 0, false, nil)
	if hc.auto() {
		t.Fatal("health check unexpectedly starts automatic")
	}

	hc.registerHealthCheckTask(C.DefaultTestURL, nil, "", 300)
	if !hc.auto() {
		t.Fatal("primary URL registration did not enable automatic health checks")
	}
	if hc.interval != 300*time.Second {
		t.Fatalf("interval = %v, want 5m", hc.interval)
	}
	if len(hc.extra) != 0 {
		t.Fatalf("primary URL registration created duplicate extra task: %#v", hc.extra)
	}

	// The provider's first effective interval remains authoritative.
	hc.registerHealthCheckTask(C.DefaultTestURL, nil, "", 60)
	if hc.interval != 300*time.Second {
		t.Fatalf("duplicate registration replaced interval with %v", hc.interval)
	}
}
