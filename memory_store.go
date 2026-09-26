package secretrotation

import (
	"context"
	"sort"
	"sync"
)

// MemoryStore 是基于内存的 Store 实现，以 Revision 作为乐观锁：
// 每次成功的 CompareAndSwap 都会令修订号 +1，读取出的状态携带当时的
// 修订号，CAS 时必须精确匹配，因此并发的激活/取消/超时只有一个能胜出。
// 它适用于单进程服务与测试；多副本部署应替换为带条件写入的持久化实现。
type MemoryStore struct {
	mu      sync.Mutex
	keys    map[string]*KeyState
	nextRev int64
}

// NewMemoryStore 创建空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: map[string]*KeyState{}, nextRev: 1}
}

// Get 返回密钥状态的深拷贝，调用方的修改不会影响存储内的状态。
func (m *MemoryStore) Get(_ context.Context, name string) (*KeyState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.keys[name]
	if !ok {
		return nil, ErrNotFound
	}
	out := cloneKeyState(st)
	return out, nil
}

// CompareAndSwap 在修订号匹配时原子替换状态。
func (m *MemoryStore) CompareAndSwap(_ context.Context, expected, next *KeyState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if expected == nil {
		if _, exists := m.keys[next.Name]; exists {
			return ErrCASConflict
		}
		stored := cloneKeyState(next)
		stored.Revision = m.nextRev
		m.nextRev++
		m.keys[stored.Name] = stored
		return nil
	}

	stored, ok := m.keys[expected.Name]
	if !ok || stored.Revision != expected.Revision {
		return ErrCASConflict
	}
	updated := cloneKeyState(next)
	updated.Name = expected.Name
	updated.Revision = m.nextRev
	m.nextRev++
	m.keys[expected.Name] = updated
	return nil
}

// ListKeys 返回按字典序排列的全部密钥名。
func (m *MemoryStore) ListKeys(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.keys))
	for name := range m.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
