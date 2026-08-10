package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"secaudit/internal/scanner"
)

type ScanJob struct {
	ID        string      `json:"id"`
	Domain    string      `json:"domain"`
	Status    string      `json:"status"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	DoneAt    time.Time   `json:"done_at,omitempty"`
}

type RecurringScan struct {
	Domain          string    `json:"domain"`
	IntervalMinutes int       `json:"interval_minutes"`
	Enabled         bool      `json:"enabled"`
	LastRun         time.Time `json:"last_run,omitempty"`
	NextRun         time.Time `json:"next_run,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type persistedState struct {
	Jobs      map[string]*ScanJob       `json:"jobs"`
	History   map[string][]string       `json:"history"`
	Recurring map[string]*RecurringScan `json:"recurring"`
}

type Store struct {
	mu        sync.RWMutex
	jobs      map[string]*ScanJob
	history   map[string][]string
	recurring map[string]*RecurringScan
	dataFile  string
}

func NewStore(dataDir string) *Store {
	s := &Store{
		jobs:      make(map[string]*ScanJob),
		history:   make(map[string][]string),
		recurring: make(map[string]*RecurringScan),
	}

	if dataDir != "" {
		os.MkdirAll(dataDir, 0o755)
		s.dataFile = filepath.Join(dataDir, "secaudit-store.json")
		s.load()
	}

	return s
}

func (s *Store) load() {
	if s.dataFile == "" {
		return
	}
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	if state.Jobs != nil {
		s.jobs = state.Jobs
		for _, job := range s.jobs {
			if job.Status == "done" && job.Result != nil {
				raw, err := json.Marshal(job.Result)
				if err == nil {
					var report scanner.FullReport
					if err := json.Unmarshal(raw, &report); err == nil {
						job.Result = &report
					}
				}
			}
		}
	}
	if state.History != nil {
		s.history = state.History
	}
	if state.Recurring != nil {
		s.recurring = state.Recurring
	}
}

func (s *Store) saveLocked() {
	if s.dataFile == "" {
		return
	}
	state := persistedState{
		Jobs:      s.jobs,
		History:   s.history,
		Recurring: s.recurring,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	tmp := s.dataFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	os.Rename(tmp, s.dataFile)
}

func (s *Store) CreateJob(domain string) *ScanJob {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateToken()[:12]
	job := &ScanJob{
		ID:        id,
		Domain:    domain,
		Status:    "queued",
		CreatedAt: time.Now(),
	}
	s.jobs[id] = job
	s.history[domain] = append(s.history[domain], id)
	s.saveLocked()
	return job
}

func (s *Store) GetJob(id string) *ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jobs[id]
}

func (s *Store) UpdateJob(id, status string, result interface{}, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Status = status
		job.Result = result
		job.Error = errMsg
		if status == "done" || status == "error" {
			job.DoneAt = time.Now()
		}
		s.saveLocked()
	}
}

func (s *Store) GetHistory(domain string) []*ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.history[domain]
	var jobs []*ScanJob
	for _, id := range ids {
		if job, ok := s.jobs[id]; ok {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func (s *Store) GetLastCompletedJobs(domain string, n int) []*ScanJob {
	all := s.GetHistory(domain)
	var done []*ScanJob
	for i := len(all) - 1; i >= 0 && len(done) < n; i-- {
		if all[i].Status == "done" {
			done = append(done, all[i])
		}
	}
	return done
}

func (s *Store) SetRecurring(domain string, intervalMinutes int, enabled bool) *RecurringScan {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, ok := s.recurring[domain]
	if !ok {
		rs = &RecurringScan{
			Domain:    domain,
			CreatedAt: time.Now(),
		}
		s.recurring[domain] = rs
	}
	rs.IntervalMinutes = intervalMinutes
	rs.Enabled = enabled
	rs.NextRun = time.Now().Add(time.Duration(intervalMinutes) * time.Minute)
	s.saveLocked()
	return rs
}

func (s *Store) RemoveRecurring(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.recurring, domain)
	s.saveLocked()
}

func (s *Store) ListRecurring() []*RecurringScan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*RecurringScan
	for _, rs := range s.recurring {
		list = append(list, rs)
	}
	return list
}

func (s *Store) DueRecurring() []*RecurringScan {
	s.mu.RLock()
	now := time.Now()
	var due []*RecurringScan
	for _, rs := range s.recurring {
		if rs.Enabled && now.After(rs.NextRun) {
			due = append(due, rs)
		}
	}
	s.mu.RUnlock()
	return due
}

func (s *Store) MarkRecurringRun(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rs, ok := s.recurring[domain]; ok {
		rs.LastRun = time.Now()
		rs.NextRun = time.Now().Add(time.Duration(rs.IntervalMinutes) * time.Minute)
		s.saveLocked()
	}
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
