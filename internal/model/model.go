package model

import (
	"context"
	"github.com/bishoku/jvmdiag/internal/analyzer/quality"
	"sync"
	"time"
)

type AnalysisType string

const (
	AnalysisHeapDump   AnalysisType = "HEAP_DUMP"
	AnalysisThreadDump AnalysisType = "THREAD_DUMP"
	AnalysisGCLog      AnalysisType = "GC_LOG"
	AnalysisDiff       AnalysisType = "DIFF"
	AnalysisIncident   AnalysisType = "INCIDENT"
	AnalysisNMTCrash   AnalysisType = "NMT_CRASH"
	AnalysisJFR        AnalysisType = "JFR"
)

type AnalysisStatus string

const (
	StatusQueued               AnalysisStatus = "QUEUED"
	StatusUploading            AnalysisStatus = "UPLOADING"
	StatusAnalyzing            AnalysisStatus = "ANALYZING"
	StatusGeneratingAIResponse AnalysisStatus = "GENERATING_AI_RESPONSE"
	StatusCompleted            AnalysisStatus = "COMPLETED"
	StatusFailed               AnalysisStatus = "FAILED"
)

type AnalysisState struct {
	done         chan struct{}
	Assessment   *quality.Assessment `json:"assessment,omitempty"`
	mu           sync.RWMutex
	ID           string         `json:"id"`
	WorkspaceID  string         `json:"workspaceId"`
	FileName     string         `json:"fileName"`
	AnalysisType AnalysisType   `json:"analysisType"`
	Status       AnalysisStatus `json:"status"`
	StaticReport string         `json:"staticReport"`
	AIResponse   string         `json:"aiResponse"`
	ErrorMessage string         `json:"errorMessage"`
	CreatedAt    time.Time      `json:"createdAt"`
	FileSize     int64          `json:"fileSizeBytes"`
	EngineUsed   string         `json:"engineUsed,omitempty"` // "native-hprof", "native+mat", etc.
}

func NewAnalysisState(id, workspaceID, fileName string, aType AnalysisType, fileSize int64) *AnalysisState {
	return &AnalysisState{
		done:         make(chan struct{}),
		ID:           id,
		WorkspaceID:  workspaceID,
		FileName:     fileName,
		AnalysisType: aType,
		Status:       StatusUploading,
		CreatedAt:    time.Now().UTC(),
		FileSize:     fileSize,
	}
}

func (s *AnalysisState) SetAssessment(a quality.Assessment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Assessment = &a
}

// Wait waits for this job generation to finish. A deadline is a failure guard, not a scheduling assumption.
func (s *AnalysisState) Wait(ctx context.Context) error {
	s.mu.RLock()
	done := s.done
	s.mu.RUnlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *AnalysisState) finishLocked() {
	if s.done == nil {
		s.done = make(chan struct{})
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *AnalysisState) SetStatus(st AnalysisStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.Status == StatusCompleted || s.Status == StatusFailed) && st != StatusCompleted && st != StatusFailed {
		s.done = make(chan struct{})
	}
	s.Status = st
	if st == StatusCompleted || st == StatusFailed {
		s.finishLocked()
	}
}

func (s *AnalysisState) SetStaticReport(report, engine string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StaticReport = report
	if engine != "" {
		s.EngineUsed = engine
	}
}

func (s *AnalysisState) SetAIResponse(resp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AIResponse = resp
}

func (s *AnalysisState) SetError(err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ErrorMessage = err
	s.Status = StatusFailed
	s.finishLocked()
	if s.Assessment == nil {
		s.Assessment = &quality.Assessment{Status: "failed", Scope: "no usable diagnostic result", Warnings: []string{err}}
	}
}

type AnalysisSnapshot struct {
	Assessment   *quality.Assessment `json:"assessment,omitempty"`
	ID           string              `json:"id"`
	WorkspaceID  string              `json:"workspaceId"`
	FileName     string              `json:"fileName"`
	AnalysisType AnalysisType        `json:"analysisType"`
	Status       AnalysisStatus      `json:"status"`
	StaticReport string              `json:"staticReport"`
	AIResponse   string              `json:"aiResponse"`
	ErrorMessage string              `json:"errorMessage"`
	CreatedAt    time.Time           `json:"createdAt"`
	FileSize     int64               `json:"fileSizeBytes"`
	EngineUsed   string              `json:"engineUsed,omitempty"` // "native-hprof", "native+mat", etc.
}

func (s *AnalysisState) Snapshot() AnalysisSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return AnalysisSnapshot{
		Assessment:   s.Assessment,
		ID:           s.ID,
		WorkspaceID:  s.WorkspaceID,
		FileName:     s.FileName,
		AnalysisType: s.AnalysisType,
		Status:       s.Status,
		StaticReport: s.StaticReport,
		AIResponse:   s.AIResponse,
		ErrorMessage: s.ErrorMessage,
		CreatedAt:    s.CreatedAt,
		FileSize:     s.FileSize,
		EngineUsed:   s.EngineUsed,
	}
}

type AnalysisRecord struct {
	Assessment   *quality.Assessment `json:"assessment,omitempty"`
	ID           string              `json:"id"`
	WorkspaceID  string              `json:"workspaceId"`
	FileName     string              `json:"fileName"`
	AnalysisType AnalysisType        `json:"analysisType"`
	StaticReport string              `json:"staticReport"`
	AIResponse   string              `json:"aiResponse"`
	EngineUsed   string              `json:"engineUsed,omitempty"`
	FileSize     int64               `json:"fileSizeBytes"`
	CreatedAt    time.Time           `json:"createdAt"`
	SavedAt      time.Time           `json:"savedAt"`
}

func RecordFromState(st AnalysisSnapshot) AnalysisRecord {
	return AnalysisRecord{
		Assessment:   st.Assessment,
		ID:           st.ID,
		WorkspaceID:  st.WorkspaceID,
		FileName:     st.FileName,
		AnalysisType: st.AnalysisType,
		StaticReport: st.StaticReport,
		AIResponse:   st.AIResponse,
		EngineUsed:   st.EngineUsed,
		FileSize:     st.FileSize,
		CreatedAt:    st.CreatedAt,
		SavedAt:      time.Now().UTC(),
	}
}

type McpLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // "IN" or "OUT"
	Payload   string    `json:"payload"`
}
