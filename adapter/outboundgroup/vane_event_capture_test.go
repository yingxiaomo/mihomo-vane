package outboundgroup

import "sync"

// The diagnostics event ring is gone; tests install a sink at group
// construction and count records afterwards, which is what the ring used to
// allow (and a superset: the sink also sees churn-*/gray-*/b2-* kinds).
type vaneRecordedEvent struct {
	Sequence      uint64
	Kind          string
	Reason        string
	HandoffID     uint64
	LeaseID       string
	ExplorationID uint64
	From          string
	To            string
	Target        string
	Port          uint16
	Occurrences   int
	LowWindows    int
}

var vaneRecorded = struct {
	sync.Mutex
	byGroup map[*Vane][]vaneRecordedEvent
	seq     map[*Vane]uint64
}{byGroup: map[*Vane][]vaneRecordedEvent{}, seq: map[*Vane]uint64{}}

func installVaneEventRecorder(group *Vane) {
	if group == nil || group.diagnostics == nil {
		return
	}
	group.diagnostics.sink = func(record vaneDiagnosticRecord) {
		vaneRecorded.Lock()
		vaneRecorded.seq[group]++
		vaneRecorded.byGroup[group] = append(vaneRecorded.byGroup[group], vaneRecordedEvent{
			Sequence:      vaneRecorded.seq[group],
			Kind:          record.kind,
			Reason:        record.reason,
			HandoffID:     record.handoffID,
			LeaseID:       record.leaseID,
			ExplorationID: record.explorationID,
			From:          record.from,
			To:            record.to,
			Target:        record.target,
			Port:          record.port,
			Occurrences:   record.occurrences,
			LowWindows:    record.lowWindows,
		})
		vaneRecorded.Unlock()
	}
}

// dropVaneRecordedEvents keeps the package-level map from growing across tests.
func dropVaneRecordedEvents(group *Vane) {
	vaneRecorded.Lock()
	delete(vaneRecorded.byGroup, group)
	delete(vaneRecorded.seq, group)
	vaneRecorded.Unlock()
}

func vaneRecordedEvents(group *Vane) []vaneRecordedEvent {
	vaneRecorded.Lock()
	defer vaneRecorded.Unlock()
	return append([]vaneRecordedEvent(nil), vaneRecorded.byGroup[group]...)
}

func countVaneEvents(group *Vane, kind, reason string) int {
	count := 0
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == kind && (reason == "" || event.Reason == reason) {
			count++
		}
	}
	return count
}
