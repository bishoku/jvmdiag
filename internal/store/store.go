package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bishoku/jvmdiag/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/internal/analyzer/mat"
	"github.com/bishoku/jvmdiag/internal/config"
	"github.com/bishoku/jvmdiag/internal/model"
)

type HeapSession struct {
	done           chan struct{}
	mu             sync.RWMutex
	SessionID      string         `json:"sessionId"`
	WorkspaceID    string         `json:"workspaceId"`
	FileName       string         `json:"fileName"`
	HprofPath      string         `json:"-"`
	FileSizeBytes  int64          `json:"fileSizeBytes"`
	Parsed         bool           `json:"parsed"`
	DeepMatParsed  bool           `json:"deepMatParsed"`
	EngineUsed     string         `json:"engineUsed"`
	ParseError     string         `json:"parseError"`
	CreatedAt      time.Time      `json:"createdAt"`
	LastAccessedAt time.Time      `json:"lastAccessedAt"`
	NativeSummary  *hprof.Summary `json:"-"`
}

// AnalysisData returns a synchronized view. Published summaries are immutable.
func (s *HeapSession) AnalysisData() (bool, string, *hprof.Summary) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Parsed, s.ParseError, s.NativeSummary
}

func (s *HeapSession) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *HeapSession) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastAccessedAt = time.Now().UTC()
}

func (s *HeapSession) SetParsed(native *hprof.Summary, engine string, deepMat bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Parsed = true
	s.NativeSummary = native
	s.EngineUsed = engine
	s.DeepMatParsed = deepMat
	s.LastAccessedAt = time.Now().UTC()
}

func (s *HeapSession) SetError(err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ParseError = err
}

func (s *HeapSession) StatusMap(timeoutMin int) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"active": true,
		"assessment": func() any {
			if s.NativeSummary != nil {
				return s.NativeSummary.Assessment
			}
			if s.ParseError != "" {
				return map[string]any{"status": "failed", "warnings": []string{s.ParseError}}
			}
			return nil
		}(),
		"sessionId":             s.SessionID,
		"workspaceId":           s.WorkspaceID,
		"fileName":              s.FileName,
		"fileSizeBytes":         s.FileSizeBytes,
		"parsed":                s.Parsed,
		"deepMatParsed":         s.DeepMatParsed,
		"engineUsed":            s.EngineUsed,
		"parseError":            s.ParseError,
		"createdAt":             s.CreatedAt.Format(time.RFC3339),
		"lastAccessedAt":        s.LastAccessedAt.Format(time.RFC3339),
		"sessionTimeoutMinutes": timeoutMin,
	}
}

type Store struct {
	stop           chan struct{}
	stopOnce       sync.Once
	cfg            *config.Manager
	matSvc         *mat.Service
	workerSem      chan struct{}
	mu             sync.RWMutex
	activeJobs     map[string]*model.AnalysisState
	historyByWS    map[string]map[string]model.AnalysisRecord
	sessions       map[string]*HeapSession
	activeSessByWS map[string]string
	mcpLogs        map[string][]model.McpLogEntry
	mcpSubs        map[string]map[chan model.McpLogEntry]struct{}
}

func NewStore(cfg *config.Manager, matSvc *mat.Service) *Store {
	maxW := cfg.MaxWorkers()
	if maxW <= 0 {
		maxW = 2
	}
	st := &Store{
		stop:           make(chan struct{}),
		cfg:            cfg,
		matSvc:         matSvc,
		workerSem:      make(chan struct{}, maxW),
		activeJobs:     make(map[string]*model.AnalysisState),
		historyByWS:    make(map[string]map[string]model.AnalysisRecord),
		sessions:       make(map[string]*HeapSession),
		activeSessByWS: make(map[string]string),
		mcpLogs:        make(map[string][]model.McpLogEntry),
		mcpSubs:        make(map[string]map[chan model.McpLogEntry]struct{}),
	}
	st.loadExistingWorkspaces()
	go st.cleanupLoop()
	return st
}

// Close stops periodic cleanup. In-flight jobs retain their own completion notifications.
func (s *Store) Close() { s.stopOnce.Do(func() { close(s.stop) }) }
func (s *Store) TryAcquireWorker() bool {
	select {
	case s.workerSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Store) AcquireWorker() {
	s.workerSem <- struct{}{}
}

func (s *Store) ReleaseWorker() {
	<-s.workerSem
}

func (s *Store) RegisterJob(job *model.AnalysisState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeJobs[job.ID] = job
}

func (s *Store) GetJob(ws, id string) *model.AnalysisState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job := s.activeJobs[id]
	if job != nil && job.WorkspaceID == config.SanitizeWorkspaceID(ws) {
		return job
	}
	return nil
}

func (s *Store) ListWorkspaces() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{config.DefaultWorkspace: true}
	for ws := range s.historyByWS {
		seen[ws] = true
	}
	for ws := range s.activeSessByWS {
		seen[ws] = true
	}
	wsRoot := filepath.Join(s.cfg.BaseDir(), "workspaces")
	if entries, err := os.ReadDir(wsRoot); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				seen[config.SanitizeWorkspaceID(e.Name())] = true
			}
		}
	}
	var out []string
	for ws := range seen {
		out = append(out, ws)
	}
	sort.Strings(out)
	return out
}

// History Operations (Workspace-isolated)

func (s *Store) loadExistingWorkspaces() {
	wsRoot := filepath.Join(s.cfg.BaseDir(), "workspaces")
	if entries, err := os.ReadDir(wsRoot); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				ws := config.SanitizeWorkspaceID(e.Name())
				s.loadWorkspaceHistory(ws)
			}
		}
	}
	s.loadWorkspaceHistory(config.DefaultWorkspace)

	// Also check legacy ./heap-dumps/analysis-history.json if default workspace is empty
	if s.cfg.LegacySourcesEnabled() && len(s.historyByWS[config.DefaultWorkspace]) == 0 {
		if data, err := os.ReadFile("./heap-dumps/analysis-history.json"); err == nil {
			var recs []model.AnalysisRecord
			if json.Unmarshal(data, &recs) == nil && len(recs) > 0 {
				if s.historyByWS[config.DefaultWorkspace] == nil {
					s.historyByWS[config.DefaultWorkspace] = make(map[string]model.AnalysisRecord)
				}
				for _, r := range recs {
					if r.WorkspaceID == "" {
						r.WorkspaceID = config.DefaultWorkspace
					}
					s.historyByWS[config.DefaultWorkspace][r.ID] = r
				}
				_ = s.persistWorkspaceHistory(config.DefaultWorkspace)
			}
		}
	}
}

func (s *Store) loadWorkspaceHistory(ws string) {
	histFile := filepath.Join(s.cfg.WorkspaceDir(ws), "analysis-history.json")
	data, err := os.ReadFile(histFile)
	if err != nil {
		return
	}
	var recs []model.AnalysisRecord
	if json.Unmarshal(data, &recs) == nil {
		if s.historyByWS[ws] == nil {
			s.historyByWS[ws] = make(map[string]model.AnalysisRecord)
		}
		for _, r := range recs {
			r.WorkspaceID = ws
			s.historyByWS[ws][r.ID] = r
		}
	}
}

func (s *Store) persistWorkspaceHistory(ws string) error {
	dir := s.cfg.WorkspaceDir(ws)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var list []model.AnalysisRecord
	for _, r := range s.historyByWS[ws] {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].SavedAt.After(list[j].SavedAt)
	})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "analysis-history.json"), data, 0o644)
}

func (s *Store) SaveHistory(rec model.AnalysisRecord) model.AnalysisRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws := config.SanitizeWorkspaceID(rec.WorkspaceID)
	rec.WorkspaceID = ws
	if s.historyByWS[ws] == nil {
		s.historyByWS[ws] = make(map[string]model.AnalysisRecord)
	}
	s.historyByWS[ws][rec.ID] = rec
	_ = s.persistWorkspaceHistory(ws)
	return rec
}

func (s *Store) ListHistory(ws string) []model.AnalysisRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws = config.SanitizeWorkspaceID(ws)
	var list []model.AnalysisRecord
	for _, r := range s.historyByWS[ws] {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].SavedAt.After(list[j].SavedAt)
	})
	return list
}

func (s *Store) FindHistory(ws, id string) (model.AnalysisRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws = config.SanitizeWorkspaceID(ws)
	if m, ok := s.historyByWS[ws]; ok {
		if r, exists := m[id]; exists {
			return r, true
		}
	}
	return model.AnalysisRecord{}, false
}

func (s *Store) DeleteHistory(ws, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws = config.SanitizeWorkspaceID(ws)
	if m, ok := s.historyByWS[ws]; ok {
		if _, exists := m[id]; exists {
			delete(m, id)
			_ = s.persistWorkspaceHistory(ws)
			return true
		}
	}
	return false
}

// MCP Session Operations (Multi-session & Workspace-isolated)

func (s *Store) CreateHeapSession(ws, sessionID, fileName, hprofPath string, fileSize int64, useDeepMat bool) *HeapSession {
	ws = config.SanitizeWorkspaceID(ws)
	now := time.Now().UTC()
	sess := &HeapSession{
		done:           make(chan struct{}),
		SessionID:      sessionID,
		WorkspaceID:    ws,
		FileName:       fileName,
		HprofPath:      hprofPath,
		FileSizeBytes:  fileSize,
		CreatedAt:      now,
		LastAccessedAt: now,
	}

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.activeSessByWS[ws] = sessionID
	s.mu.Unlock()

	go func() {
		defer close(sess.done)
		s.AcquireWorker()
		defer s.ReleaseWorker()

		// Publish one immutable result only after requested engines have reported their status.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		_, nativeSum, engine, err := mat.AnalyzeHeapHybrid(ctx, s.matSvc, hprofPath, useDeepMat)
		if err != nil {
			sess.SetError(err.Error())
			return
		}
		sess.SetParsed(nativeSum, engine, engine == "native-hprof+eclipse-mat")
	}()

	return sess
}

func (s *Store) GetActiveSession(ws string) *HeapSession {
	s.mu.RLock()
	ws = config.SanitizeWorkspaceID(ws)
	sid := s.activeSessByWS[ws]
	sess := s.sessions[sid]
	s.mu.RUnlock()
	if sess != nil {
		sess.Touch()
	}
	return sess
}

func (s *Store) GetSession(ws, sessionID string) *HeapSession {
	s.mu.RLock()
	sess := s.sessions[sessionID]
	if sess != nil && sess.WorkspaceID != config.SanitizeWorkspaceID(ws) {
		sess = nil
	}
	s.mu.RUnlock()
	if sess != nil {
		sess.Touch()
	}
	return sess
}

func (s *Store) ListSessions(ws string) []*HeapSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws = config.SanitizeWorkspaceID(ws)
	var list []*HeapSession
	for _, sess := range s.sessions {
		if sess.WorkspaceID == ws {
			list = append(list, sess)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list
}

func (s *Store) CloseSession(ws, sessionID string) {
	s.mu.Lock()
	ws = config.SanitizeWorkspaceID(ws)
	if sessionID == "" {
		sessionID = s.activeSessByWS[ws]
	}
	sess, ok := s.sessions[sessionID]
	ok = ok && sess.WorkspaceID == ws
	if ok {
		delete(s.sessions, sessionID)
		if s.activeSessByWS[sess.WorkspaceID] == sessionID {
			delete(s.activeSessByWS, sess.WorkspaceID)
		}
	}
	s.mu.Unlock()

	if ok && sess != nil {
		cleanupSessionFiles(sess.HprofPath)
	}
}

func cleanupSessionFiles(hprofPath string) {
	if hprofPath == "" {
		return
	}
	dir := filepath.Dir(hprofPath)
	base := filepath.Base(hprofPath)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), prefix) {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	_ = os.Remove(dir) // remove dir if empty
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
		cutoff := time.Now().UTC().Add(-120 * time.Minute)
		type expiredSession struct{ ws, id string }
		var expired []expiredSession
		s.mu.RLock()
		for id, sess := range s.sessions {
			sess.mu.RLock()
			last := sess.LastAccessedAt
			sess.mu.RUnlock()
			if last.Before(cutoff) {
				expired = append(expired, expiredSession{sess.WorkspaceID, id})
			}
		}
		s.mu.RUnlock()
		for _, sess := range expired {
			s.CloseSession(sess.ws, sess.id)
		}
	}
}

// MCP JSON-RPC Activity Logging

func (s *Store) RecordMcpLog(sessionID, direction, payload string) {
	if sessionID == "" {
		sessionID = "global"
	}
	entry := model.McpLogEntry{
		Timestamp: time.Now().UTC(),
		Direction: direction,
		Payload:   payload,
	}
	s.mu.Lock()
	logs := append(s.mcpLogs[sessionID], entry)
	if len(logs) > 200 {
		logs = logs[len(logs)-200:]
	}
	s.mcpLogs[sessionID] = logs
	var chans []chan model.McpLogEntry
	for ch := range s.mcpSubs[sessionID] {
		chans = append(chans, ch)
	}
	s.mu.Unlock()

	for _, ch := range chans {
		select {
		case ch <- entry:
		default:
		}
	}
}

func (s *Store) GetRecentMcpLogs(sessionID string) []model.McpLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	logs := s.mcpLogs[sessionID]
	out := make([]model.McpLogEntry, len(logs))
	copy(out, logs)
	return out
}

func (s *Store) SubscribeMcpLogs(sessionID string) (chan model.McpLogEntry, func()) {
	ch := make(chan model.McpLogEntry, 32)
	s.mu.Lock()
	if s.mcpSubs[sessionID] == nil {
		s.mcpSubs[sessionID] = make(map[chan model.McpLogEntry]struct{})
	}
	s.mcpSubs[sessionID][ch] = struct{}{}
	s.mu.Unlock()

	unsubscribe := func() {
		s.mu.Lock()
		if subs, ok := s.mcpSubs[sessionID]; ok {
			delete(subs, ch)
		}
		s.mu.Unlock()
	}
	return ch, unsubscribe
}
