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

type Program struct {
	Path string
	Args []string
}

// TODO: Change to ProgramFingerprint
type ProcessFingerprint struct {
	Program *Program
	// FilesystemActivityFingerprint Fingerprint
	// NetworkActivityFingerprint    Fingerprint
	// ExecutionFingerprint          Fingerprint
	Children map[*Program]*ProcessFingerprint
}

func NewProcessFingerprint(program *Program) *ProcessFingerprint {
	return &ProcessFingerprint{
		Program: program,
		// FilesystemActivityFingerprint: nil, // TODO: Implement
		// NetworkActivityFingerprint:    nil, // TODO: Implement
		Children: make(map[*Program]*ProcessFingerprint),
	}
}

func (processFingerprint *ProcessFingerprint) Update(event *trace.Event) {
	fingerprint, err := processFingerprint.route(event)
	if err != nil {
		log.Printf("Error updating fingerprint for incoming event: %v - %v \n", event, err)
		return
	}

	fingerprint.Update(event)
}

// TODO: Benchmark and see if map is faster than scan
func (processFingerprint *ProcessFingerprint) route(event *trace.Event) (Fingerprint, error) {
	return nil, errors.New("Not implemented")
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

func (processFingerprint *ProcessFingerprint) AddChild(childProcessFingerprint *ProcessFingerprint) {
	processFingerprint.Children[childProcessFingerprint.Cmd] = childProcessFingerprint
}
