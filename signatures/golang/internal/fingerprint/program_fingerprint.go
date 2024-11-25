package fingerprint

import (
	"errors"
	"log"

	"github.com/aquasecurity/tracee/types/trace"
)

type Fingerprint interface {
	Update(event *trace.Event)
	// Enforce(event *trace.Event) bool // Will be implemented once the enforce mode is implemented
}

// TODO: Change to ProgramFingerprint
type ProgramFingerprint struct {
	Program Program
	// FilesystemActivityFingerprint Fingerprint
	// NetworkActivityFingerprint    Fingerprint
	// ExecutionFingerprint          Fingerprint
}

func NewProgramFingerprint(program Program) *ProgramFingerprint {
	return &ProgramFingerprint{
		Program: program,
		// FilesystemActivityFingerprint: nil, // TODO: Implement
		// NetworkActivityFingerprint:    nil, // TODO: Implement
	}
}

func (programFingerprint *ProgramFingerprint) Update(event *trace.Event) {
	fingerprint, err := programFingerprint.route(event)
	if err != nil {
		log.Printf("error updating fingerprint for incoming event: %v - %v \n", event, err)
		return
	}

	fingerprint.Update(event)
}

// TODO: Benchmark and see if map is faster than scan
func (programFingerprint *ProgramFingerprint) route(event *trace.Event) (Fingerprint, error) {
	return nil, errors.New("not implemented")
	// for _, eventSelector := range FilesystemActivityEvents {
	// 	if eventSelector.Name == event.EventName {
	// 		return processFingerprint.FilesystemActivityFingerprint, nil
	// 	}
	// }

	// for _, eventSelector := range NetworkActivityEvents {
	// 	if eventSelector.Name == event.EventName {
	// 		return processFingerprint.NetworkActivityFingerprint, nil
	// 	}
	// }

	// return nil, errors.New("No fingerprint found to handle the incoming event")
}
