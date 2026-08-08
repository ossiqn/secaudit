package api

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type VerifyRequest struct {
	Domain    string    `json:"domain"`
	Token     string    `json:"token"`
	Method    string    `json:"method"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ScanJob struct {
	ID        string      `json:"id"`
	Domain    string      `json:"domain"`
	Status    string      `json:"status"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	DoneAt    time.Time   `json:"done_at,omitempty"`
}

type Store struct {
	mu       sync.RWMutex
	verifies map[string]*VerifyRequest
	jobs     map[string]*ScanJob
	history  map[string][]string
}

func NewStore() *Store {
	return &Store{
		verifies: make(map[string]*VerifyRequest),
		jobs:     make(map[string]*ScanJob),
		history:  make(map[string][]string),
	}
}

func (s *Store) CreateVerify(domain, method string) *VerifyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	token := generateToken()
	vr := &VerifyRequest{
		Domain:    domain,
		Token:     token,
		Method:    method,
		Verified:  false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.verifies[domain] = vr
	return vr
}

func (s *Store) GetVerify(domain string) *VerifyRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.verifies[domain]
}

func (s *Store) MarkVerified(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vr, ok := s.verifies[domain]; ok {
		vr.Verified = true
	}
}

func (s *Store) IsVerified(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vr, ok := s.verifies[domain]
	if !ok {
		return false
	}
	return vr.Verified && time.Now().Before(vr.ExpiresAt)
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

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}