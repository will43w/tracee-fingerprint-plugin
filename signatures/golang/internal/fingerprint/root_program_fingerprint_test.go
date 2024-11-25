package fingerprint

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
	"gotest.tools/assert"
)

type FakeProcessTree struct {
	processByEntityId        map[uint32]datasource.TimeRelevantInfo[datasource.ProcessInfo]
	processLineageByEntityId map[uint32]datasource.ProcessLineage
}

func NewFakeProcessTree(processLineages []datasource.ProcessLineage) *FakeProcessTree {
	processByEntityId := make(map[uint32]datasource.TimeRelevantInfo[datasource.ProcessInfo])
	processLineageByEntityId := make(map[uint32]datasource.ProcessLineage)
	for _, processLineage := range processLineages {
		processLineageByEntityId[processLineage[0].Info.EntityId] = processLineage

		for _, process := range processLineage {
			processByEntityId[process.Info.EntityId] = process
		}
	}

	return &FakeProcessTree{
		processByEntityId:        processByEntityId,
		processLineageByEntityId: processLineageByEntityId,
	}
}

func (fpt *FakeProcessTree) GetProcessInfoByHash(hash uint32) (datasource.TimeRelevantInfo[datasource.ProcessInfo], bool) {
	processInfo, found := fpt.processByEntityId[hash]
	return processInfo, found
}

func (fpt *FakeProcessTree) GetProcessLineageByHash(hash uint32) (datasource.ProcessLineage, bool) {
	processLineage, found := fpt.processLineageByEntityId[hash]
	return processLineage, found
}

type MockProcessTreeDataSource struct {
	procTree *FakeProcessTree
}

func (ptds *MockProcessTreeDataSource) Get(key interface{}) (map[string]interface{}, error) {
	switch typedKey := key.(type) {
	case datasource.ProcKey:
		result, found := ptds.procTree.GetProcessInfoByHash(typedKey.EntityId)
		if !found {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_info": result,
		}, nil
	case datasource.LineageKey:
		result, found := ptds.procTree.GetProcessLineageByHash(typedKey.EntityId)
		if !found {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_lineage": result[:min(len(result), typedKey.MaxDepth)-1],
		}, nil
	}
	return nil, detect.ErrKeyNotSupported
}

func (ptds *MockProcessTreeDataSource) Version() uint {
	return 1
}

func (ptds *MockProcessTreeDataSource) Keys() []string {
	return []string{"datasource.ProcKey", "datasource.ThreadKey", "datasource.LineageKey"}
}

func (ptds *MockProcessTreeDataSource) Schema() string {
	schemaMap := map[string]string{
		"process_info":    "datasource.TimeRelevantInfo[datasource.ProcessInfo]",
		"thread_info":     "datasource.TimeRelevantInfo[datasource.ThreadInfo]",
		"process_lineage": "datasource.TimeRelevantInfo[datasource.ProcessLineage]",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ptds *MockProcessTreeDataSource) Namespace() string {
	return "tracee"
}

func (ptds *MockProcessTreeDataSource) ID() string {
	return "process_tree"
}

var beginningOfTime = time.Date(0, 0, 0, 0, 0, 0, 0, &time.Location{})

func GenerateFakeProcessInfoFromProgram(entityId uint32, program *Program) datasource.TimeRelevantInfo[datasource.ProcessInfo] {
	return datasource.TimeRelevantInfo[datasource.ProcessInfo]{
		Timestamp: beginningOfTime,
		Info: datasource.ProcessInfo{
			EntityId: entityId,
			Cmd:      []string{program.Cmd},
			ExecutionBinary: datasource.FileInfo{
				Path: program.ExecutionBinaryPath,
			},
			Interpreter: datasource.FileInfo{
				Path: program.InterpreterPath,
			},
		},
	}
}

func TestRootProgramFingerprint_GetOrCreateProgramFingerprintForEvent_DifferentFileInfo(t *testing.T) {
	rootProgram := &Program{
		Cmd:                 "root",
		ExecutionBinaryPath: "root",
		InterpreterPath:     "root",
	}
	var rootProcessEntityId uint32 = 0

	childProgram := &Program{
		Cmd:                 "child",
		ExecutionBinaryPath: "child",
	}
	var childProcessEntityId uint32 = 1

	irrelevantProgram := &Program{
		Cmd:                 "irrelevant",
		ExecutionBinaryPath: "irrelevant",
	}
	var irrelevantProcessEntityId uint32 = 2

	rootProcess := GenerateFakeProcessInfoFromProgram(rootProcessEntityId, rootProgram)
	childProcess := GenerateFakeProcessInfoFromProgram(childProcessEntityId, childProgram)
	irrelevantProcess := GenerateFakeProcessInfoFromProgram(irrelevantProcessEntityId, irrelevantProgram)

	processLineages := []datasource.ProcessLineage{
		{
			childProcess,
			rootProcess,
		},
		{
			irrelevantProcess,
		},
	}

	processTreeDataSource := &MockProcessTreeDataSource{
		procTree: NewFakeProcessTree(processLineages),
	}

	rootProgramFingerprint := NewRootProgramFingerprint(rootProgram)
	assert.Equal(t, rootProgramFingerprint.rootProgramFingerprint.Program, rootProgram)

	// Verify that the program in which the event occured is correctly identified as the root program, and that no descendant programs are created.
	event := trace.Event{
		ProcessEntityId: rootProcess.Info.EntityId,
	}
	fingerprint, ok := rootProgramFingerprint.GetOrCreateProgramFingerprintForEvent(processTreeDataSource, &event)
	assert.Equal(t, ok, true)
	assert.Equal(t, fingerprint.Program, *rootProgram)
	assert.Equal(t, len(rootProgramFingerprint.descendantProgramFingerprints), 0)

	// Verify that the program in which the event occured is correctly identified as the child program.
	event = trace.Event{
		ProcessEntityId: childProcess.Info.EntityId,
	}
	fingerprint, ok = rootProgramFingerprint.GetOrCreateProgramFingerprintForEvent(processTreeDataSource, &event)
	assert.Equal(t, ok, true)
	assert.Equal(t, fingerprint.Program, *childProgram)
	assert.Equal(t, len(rootProgramFingerprint.descendantProgramFingerprints), 1)
	childFingerprint, ok := rootProgramFingerprint.descendantProgramFingerprints[*childProgram]
	assert.Equal(t, ok, true)
	assert.Equal(t, childFingerprint.Program, *childProgram)

	// Verify that the program in which the event occured is not found in the process tree, and that no fingerprint is created nor returned.
	event = trace.Event{
		ProcessEntityId: 17, // EntityId unregistered in process tree
	}
	fingerprint, ok = rootProgramFingerprint.GetOrCreateProgramFingerprintForEvent(processTreeDataSource, &event)
	assert.Equal(t, ok, false)
	assert.Equal(t, fingerprint, nil)
	assert.Equal(t, len(rootProgramFingerprint.descendantProgramFingerprints), 1)

	// Verify that the program in which the event occured is not identified as being downstream of the root program, or the root program itself, and that no fingerprint is created.
	event = trace.Event{
		ProcessEntityId: irrelevantProcess.Info.EntityId,
	}
	fingerprint, ok = rootProgramFingerprint.GetOrCreateProgramFingerprintForEvent(processTreeDataSource, &event)
	assert.Equal(t, ok, false)
	assert.Equal(t, fingerprint, nil)
	assert.Equal(t, len(rootProgramFingerprint.descendantProgramFingerprints), 1)
}
