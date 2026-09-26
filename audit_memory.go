package secretrotation

import (
	"context"
	"sync"
)

// MemoryAuditSink 是 AuditSink 的内存实现，线程安全，主要用于测试与
// 本地开发。事件只含元数据；写入永不失败。
type MemoryAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

// NewMemoryAuditSink 创建空的内存审计接收器。
func NewMemoryAuditSink() *MemoryAuditSink {
	return &MemoryAuditSink{}
}

// Write 追加一条审计事件。
func (a *MemoryAuditSink) Write(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

// Events 返回审计事件的快照副本。
func (a *MemoryAuditSink) Events() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, len(a.events))
	copy(out, a.events)
	return out
}

// EventsByAction 返回指定动作名的全部审计事件。
func (a *MemoryAuditSink) EventsByAction(action string) []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []AuditEvent
	for _, ev := range a.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}
