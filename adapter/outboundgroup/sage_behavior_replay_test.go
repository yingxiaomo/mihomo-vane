package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// The same probe is executed against the protected pre-rename tree via overlay.
func TestSageRenameBehaviorReplay(t *testing.T) {
	clock := newSageConnTestClock()
	a := newSageTestProxy("alpha", true, true)
	b := newSageTestProxy("beta", true, true)
	group, _ := newSageGroupForTest(clock, 100, time.Hour, a, b)
	defer group.Close()
	meta := &C.Metadata{NetWork: C.TCP, Host: "replay.example", DstPort: 443}
	choices := []string{group.pick(meta, sageTransportTCP, true, true).Name()}
	for i := 0; i < 12; i++ {
		group.observeConnect("alpha", sageTransportTCP, clock.Now(), 900*time.Millisecond)
		group.observeConnect("beta", sageTransportTCP, clock.Now(), 20*time.Millisecond)
		clock.Advance(time.Second)
	}
	choices = append(choices, group.pick(meta, sageTransportTCP, true, true).Name())
	group.recordDialFailure(context.Background(), meta, sageTransportTCP, b, errors.New("replay failure"), clock.Now())
	choices = append(choices, group.pick(meta, sageTransportTCP, true, true).Name())
	clock.Advance(2 * time.Minute)
	choices = append(choices, group.pick(meta, sageTransportTCP, true, true).Name())
	scores := []int64{}
	var metrics sageMetrics
	for i := 0; i < 16; i++ {
		metrics.observeFailure(clock.Now(), i%7 == 0)
		metrics.observeConnect(clock.Now(), 40*time.Millisecond)
		metrics.observeResponse(clock.Now(), 70*time.Millisecond)
		metrics.observeThroughput(clock.Now(), 8000000)
		clock.Advance(time.Second)
	}
	for _, scene := range []sageScene{sageSceneDefault, sageSceneInteractive, sageSceneMedia, sageSceneBulk} {
		scores = append(scores, scoreSageMetrics(scene, metrics.snapshot(clock.Now())))
	}
	payload, err := json.Marshal(struct {
		Choices []string `json:"choices"`
		Scores  []int64  `json:"scores"`
	}{choices, scores})
	require.NoError(t, err)
	t.Log("RENAME_REPLAY=" + string(payload))
	require.Len(t, choices, 4)
	require.Len(t, scores, 4)
}
