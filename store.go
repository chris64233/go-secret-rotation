package secretrotation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Store 负责状态与审计的持久化。实现必须保证并发安全。
// 持久化内容只有密文与元信息，绝不包含密钥明文。
type Store interface {
	// Save 原子地保存全量状态快照。
	Save(state *persistedState) error
	// Load 读取最近一次保存的状态快照；没有任何状态时返回空快照。
	Load() (*persistedState, error)
	// AppendAudit 追加审计事件。
	AppendAudit(events ...AuditEvent) error
	// Audit 返回全部审计事件（按追加顺序）。
	Audit() ([]AuditEvent, error)
}

// MemoryStore 是进程内的 Store 实现，主要用于测试。
// 它通过深拷贝模拟真实持久化，避免与调用方共享引用。
type MemoryStore struct {
	mu     sync.Mutex
	state  *persistedState
	events []AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{state: newPersistedState()}
}

func (m *MemoryStore) Save(state *persistedState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp, err := deepCopyState(state)
	if err != nil {
		return err
	}
	m.state = cp
	return nil
}

func (m *MemoryStore) Load() (*persistedState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return deepCopyState(m.state)
}

func (m *MemoryStore) AppendAudit(events ...AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	return nil
}

func (m *MemoryStore) Audit() ([]AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuditEvent, len(m.events))
	copy(out, m.events)
	return out, nil
}

func deepCopyState(s *persistedState) (*persistedState, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("store: marshal state: %w", err)
	}
	var out persistedState
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshal state: %w", err)
	}
	if out.Versions == nil {
		out.Versions = map[string]*Version{}
	}
	if out.Rotations == nil {
		out.Rotations = map[string]*Rotation{}
	}
	return &out, nil
}

// FileStore 将状态写入 dir/state.json（临时文件 + rename 保证原子性），
// 审计事件追加写入 dir/audit.jsonl。
type FileStore struct {
	dir string
	mu  sync.Mutex
}

func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

func (f *FileStore) statePath() string { return filepath.Join(f.dir, "state.json") }
func (f *FileStore) auditPath() string { return filepath.Join(f.dir, "audit.jsonl") }

func (f *FileStore) Save(state *persistedState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("filestore: marshal state: %w", err)
	}
	tmp := f.statePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("filestore: write state: %w", err)
	}
	if err := os.Rename(tmp, f.statePath()); err != nil {
		return fmt.Errorf("filestore: commit state: %w", err)
	}
	return nil
}

func (f *FileStore) Load() (*persistedState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := os.ReadFile(f.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return newPersistedState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: read state: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("filestore: parse state: %w", err)
	}
	if state.Versions == nil {
		state.Versions = map[string]*Version{}
	}
	if state.Rotations == nil {
		state.Rotations = map[string]*Rotation{}
	}
	return &state, nil
}

func (f *FileStore) AppendAudit(events ...AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.OpenFile(f.auditPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("filestore: open audit log: %w", err)
	}
	defer fh.Close()
	enc := json.NewEncoder(fh)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("filestore: write audit event: %w", err)
		}
	}
	return nil
}

func (f *FileStore) Audit() ([]AuditEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := os.ReadFile(f.auditPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: read audit log: %w", err)
	}
	var events []AuditEvent
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var ev AuditEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("filestore: parse audit log: %w", err)
		}
		events = append(events, ev)
	}
	return events, nil
}
