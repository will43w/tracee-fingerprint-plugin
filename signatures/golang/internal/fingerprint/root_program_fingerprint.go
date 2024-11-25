package fingerprint

import (
	"log"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

type Program struct {
	Cmd                 string
	ExecutionBinaryPath string
	InterpreterPath     string // TODO: Needed?
}

func GetProgramFromProcessInfo(processInfo datasource.ProcessInfo) Program {
	return Program{
		Cmd:                 strings.Join(processInfo.Cmd, " "),
		ExecutionBinaryPath: processInfo.ExecutionBinary.Path,
		InterpreterPath:     processInfo.Interpreter.Path,
	}
}

type RootProgramFingerprint struct {
	// TODO: If the root program calls `exec`, it's possible for the corresponding
	// root process metadata to change. Subsequent events in descendant processes
	// won't be flagged as being relevant to the root program. Should there be
	// a possibility for multiple root `ProgramFingerprint`s, if case this occurs,
	// and for descendant processes to indeed be flagged as descendant if they
	// are downstream from some process running _any_ of the root programs?
	// For now, the process executing the root program is assumed to be unchanging,
	// not calling any new `exec`s in the process itself.
	rootProgramFingerprint *ProgramFingerprint
	// A descendant program is defined as a program run in the process
	// subtree of the process in which the root program runs. Note that
	// the process subtree is "flattened" to achieve this - where a program
	// is run in the process substree, as long as it is the same program,
	// is assumed to have the same fingerprint.
	descendantProgramFingerprints map[Program]*ProgramFingerprint
	// TODO: Add (procKey, Program) -> *ProgramFingerprint cache here, so that the
	// lineage doesn't need to be frequently searched to check if the program is
	// descendant of the root program.
}

func NewRootProgramFingerprint(rootProgram *Program) *RootProgramFingerprint {
	return &RootProgramFingerprint{
		rootProgramFingerprint:        NewProgramFingerprint(*rootProgram),
		descendantProgramFingerprints: make(map[Program]*ProgramFingerprint),
	}
}

// For a given event, determine in what program it occured, and if this program is descendant of the root program, return (a possibly newly created) fingerprint for the program.
func (rootProgramFingerprint *RootProgramFingerprint) GetOrCreateProgramFingerprintForEvent(processTreeDataSource detect.DataSource, event *trace.Event) (*ProgramFingerprint, bool) {
	// High-level algorithm:
	//  * Is process descendant of _any_ process that corresponds to a root program? If not, nothing to do for it. We're only interested in fingerprint the relevant program.
	//  * Retrieve the Program of the process.
	//  * If a program fingerprint exists, return it.
	//  * Otherwise, create one.
	//      * Keep track of root program process id. If the process id matches, create another root fingerprint. Otherwise, create a descendant fingerprint.

	// Fetch the full process lineage of the event's process
	maxDepth := 25 // TODO: Allow arbitrary depth
	lineageQueryAnswer, err := processTreeDataSource.Get(
		datasource.LineageKey{
			EntityId: event.ProcessEntityId,
			Time:     time.Unix(0, int64(event.Timestamp)),
			MaxDepth: maxDepth,
		},
	)
	if err != nil {
		log.Printf("Could not find process lineage for event ProcessEntityId: %v", event.ProcessEntityId)
		return nil, false
	}
	lineageInfo, ok := lineageQueryAnswer["process_lineage"].(datasource.ProcessLineage)
	if !ok {
		log.Printf("Could not extract process lineage from retrieved process lineage information: %v", lineageQueryAnswer)
		return nil, false
	}

	program := GetProgramFromProcessInfo(lineageInfo[0].Info)
	if program == rootProgramFingerprint.rootProgramFingerprint.Program {
		return rootProgramFingerprint.rootProgramFingerprint, true
	}

	if programFingerprint, ok := rootProgramFingerprint.descendantProgramFingerprints[program]; ok {
		return programFingerprint, true
	}

	// Search for a process in the lineage that is running the root program being fingerprinted.
	// If it can't be found, it means that this event is not a descendant of the program being fingerprinted, and
	// no fingerprint should be created nor returned.
	isDescendantOfRootProcess := false
	for _, ancestor := range lineageInfo {
		if GetProgramFromProcessInfo(ancestor.Info) == rootProgramFingerprint.rootProgramFingerprint.Program {
			isDescendantOfRootProcess = true
			break
		}
	}
	if !isDescendantOfRootProcess {
		return nil, false
	}

	programFingerprint := NewProgramFingerprint(program)
	rootProgramFingerprint.descendantProgramFingerprints[program] = programFingerprint
	return programFingerprint, true
}
