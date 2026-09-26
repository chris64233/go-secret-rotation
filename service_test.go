package secretrotation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// fakeClock 是测试用的可推进时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestService(t *testing.T, store Store) (*Service, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	svc, err := NewService(store, testKey, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, clock
}

func mustCreateVersion(t *testing.T, svc *Service, secretID, plaintext string) *Version {
	t.Helper()
	v, err := svc.CreateVersion(context.Background(), secretID, []byte(plaintext))
	if err != nil {
		t.Fatalf("CreateVersion: %v", err)
	}
	return v
}

func mustStartRotation(t *testing.T, svc *Service, secretID, toVersion string, consumers []string, policy RotationPolicy) *Rotation {
	t.Helper()
	r, err := svc.StartRotation(context.Background(), secretID, toVersion, consumers, policy)
	if err != nil {
		t.Fatalf("StartRotation: %v", err)
	}
	return r
}

func mustAck(t *testing.T, svc *Service, rotationID, consumer, requestID string) *AckOutcome {
	t.Helper()
	out, err := svc.Acknowledge(context.Background(), rotationID, consumer, requestID, []byte("loaded"))
	if err != nil {
		t.Fatalf("Acknowledge(%s): %v", consumer, err)
	}
	return out
}

func defaultPolicy() RotationPolicy {
	return RotationPolicy{AckTimeout: time.Hour, GracePeriod: 30 * time.Minute}
}

// 完整流程：创建 -> 轮换激活 -> 读取 -> 再轮换 -> 宽限期 -> 过期。
func TestFullRotationLifecycle(t *testing.T) {
	svc, clock := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v1 := mustCreateVersion(t, svc, "db", "secret-v1")
	r1 := mustStartRotation(t, svc, "db", v1.ID, []string{"app-1"}, defaultPolicy())
	out := mustAck(t, svc, r1.ID, "app-1", "req-1")
	if !out.Activated {
		t.Fatal("expected activation after ack")
	}

	plain, err := svc.Read(ctx, "db", v1.ID, "app-1", "bootstrap")
	if err != nil {
		t.Fatalf("Read v1: %v", err)
	}
	if string(plain) != "secret-v1" {
		t.Fatalf("unexpected plaintext %q", plain)
	}

	// 第二次轮换：3 个消费者，门槛 2。
	v2 := mustCreateVersion(t, svc, "db", "secret-v2")
	r2 := mustStartRotation(t, svc, "db", v2.ID, []string{"app-1", "app-2", "app-3"},
		RotationPolicy{MinAcks: 2, AckTimeout: time.Hour, GracePeriod: 30 * time.Minute})

	out = mustAck(t, svc, r2.ID, "app-1", "req-2")
	if out.Activated {
		t.Fatal("should not activate with 1/2 acks")
	}
	out = mustAck(t, svc, r2.ID, "app-2", "req-3")
	if !out.Activated {
		t.Fatal("should activate at 2/2 acks")
	}

	st, err := svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ActiveVersion != v2.ID {
		t.Fatalf("active version = %s, want %s", st.ActiveVersion, v2.ID)
	}

	// 旧版本在宽限期内仍可读。
	if _, err := svc.Read(ctx, "db", v1.ID, "app-1", "drain"); err != nil {
		t.Fatalf("Read v1 during grace: %v", err)
	}

	// 宽限期结束后旧版本读取必须失败。
	clock.Advance(31 * time.Minute)
	if _, err := svc.Read(ctx, "db", v1.ID, "app-1", "late"); !IsKind(err, KindExpired) {
		t.Fatalf("Read v1 after grace: got %v, want KindExpired", err)
	}
	// 新版本不受影响。
	if _, err := svc.Read(ctx, "db", v2.ID, "app-1", "normal"); err != nil {
		t.Fatalf("Read v2: %v", err)
	}
}

func TestAckIdempotencyAndConflict(t *testing.T) {
	svc, _ := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "secret")
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a", "b"}, defaultPolicy())

	// 首次确认。
	out, err := svc.Acknowledge(ctx, r.ID, "a", "req-1", []byte("loaded"))
	if err != nil || !out.Applied {
		t.Fatalf("first ack: out=%+v err=%v", out, err)
	}
	// 相同请求号 + 相同内容：幂等成功，不推进状态。
	out, err = svc.Acknowledge(ctx, r.ID, "a", "req-1", []byte("loaded"))
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if out.Applied {
		t.Fatal("replay must not be applied")
	}
	if len(out.Rotation.Acks) != 1 {
		t.Fatalf("replay advanced state: %+v", out.Rotation.Acks)
	}
	// 相同请求号 + 不同内容：冲突。
	if _, err := svc.Acknowledge(ctx, r.ID, "a", "req-1", []byte("tampered")); !IsKind(err, KindConflict) {
		t.Fatalf("same request id different payload: got %v, want KindConflict", err)
	}
	// 同一消费者换请求号：重复。
	if _, err := svc.Acknowledge(ctx, r.ID, "a", "req-2", []byte("loaded")); !IsKind(err, KindDuplicate) {
		t.Fatalf("different request id: got %v, want KindDuplicate", err)
	}
	// 非快照成员。
	if _, err := svc.Acknowledge(ctx, r.ID, "stranger", "req-9", []byte("loaded")); !IsKind(err, KindNotMember) {
		t.Fatalf("non-member ack: got %v, want KindNotMember", err)
	}
	// 状态未被以上任何请求推进。
	st, _ := svc.Status(ctx, "db")
	if st.Rotations[0].AckCount != 1 {
		t.Fatalf("ack count = %d, want 1", st.Rotations[0].AckCount)
	}
}

func TestSnapshotFrozenAgainstMembershipChange(t *testing.T) {
	svc, _ := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "secret")
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a"}, defaultPolicy())

	// 轮换发起后才加入的消费者不在快照内，其确认不能推进状态。
	if _, err := svc.Acknowledge(ctx, r.ID, "newcomer", "req-1", nil); !IsKind(err, KindNotMember) {
		t.Fatalf("got %v, want KindNotMember", err)
	}
	out := mustAck(t, svc, r.ID, "a", "req-2")
	if !out.Activated {
		t.Fatal("snapshot member ack should activate")
	}
}

func TestLateAckAndLateCancelCannotMoveTerminalState(t *testing.T) {
	svc, _ := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "secret")
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a", "b"}, defaultPolicy())
	mustAck(t, svc, r.ID, "a", "req-1")
	mustAck(t, svc, r.ID, "b", "req-2") // 激活

	// 迟到确认：不推进状态。
	if _, err := svc.Acknowledge(ctx, r.ID, "a", "req-3", []byte("x")); !IsKind(err, KindDuplicate) {
		t.Fatalf("late duplicate ack: got %v, want KindDuplicate", err)
	}
	// 已确认消费者的幂等重放在轮换关闭后仍然成功且不改变状态。
	out, err := svc.Acknowledge(ctx, r.ID, "a", "req-1", []byte("loaded"))
	if err != nil || out.Applied {
		t.Fatalf("idempotent replay after close: out=%+v err=%v", out, err)
	}
	// 迟到取消：不能把版本回退。
	if err := svc.CancelRotation(ctx, r.ID, "ops"); !IsKind(err, KindInvalidState) {
		t.Fatalf("late cancel: got %v, want KindInvalidState", err)
	}
	st, _ := svc.Status(ctx, "db")
	if st.ActiveVersion != v.ID {
		t.Fatalf("active version rolled back to %q", st.ActiveVersion)
	}
}

func TestCancelRotation(t *testing.T) {
	svc, _ := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "secret")
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a"}, defaultPolicy())

	if err := svc.CancelRotation(ctx, r.ID, "ops"); err != nil {
		t.Fatalf("CancelRotation: %v", err)
	}
	// 待激活版本作废，不可读。
	if _, err := svc.Read(ctx, "db", v.ID, "a", "check"); !IsKind(err, KindInvalidState) {
		t.Fatalf("read cancelled version: got %v, want KindInvalidState", err)
	}
	// 取消后确认无效。
	if _, err := svc.Acknowledge(ctx, r.ID, "a", "req-1", nil); !IsKind(err, KindInvalidState) {
		t.Fatalf("ack after cancel: got %v, want KindInvalidState", err)
	}
	// 重复取消报错。
	if err := svc.CancelRotation(ctx, r.ID, "ops"); !IsKind(err, KindInvalidState) {
		t.Fatalf("re-cancel: got %v, want KindInvalidState", err)
	}
}

func TestRotationTimeout(t *testing.T) {
	svc, clock := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "secret")
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a"},
		RotationPolicy{AckTimeout: time.Hour, GracePeriod: time.Minute})

	clock.Advance(2 * time.Hour)
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	st, _ := svc.Status(ctx, "db")
	if st.Rotations[0].State != RotationTimedOut {
		t.Fatalf("rotation state = %s, want timed_out", st.Rotations[0].State)
	}
	// 超时后确认无效。
	if _, err := svc.Acknowledge(ctx, r.ID, "a", "req-1", nil); !IsKind(err, KindExpired) {
		t.Fatalf("ack after timeout: got %v, want KindExpired", err)
	}
	// 待激活版本作废。
	if _, err := svc.Read(ctx, "db", v.ID, "a", "check"); !IsKind(err, KindInvalidState) {
		t.Fatalf("read timed-out version: got %v, want KindInvalidState", err)
	}
}

func TestConcurrentActivationCancelSingleTerminalState(t *testing.T) {
	svc, _ := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "secret")
	consumers := []string{"a", "b", "c", "d", "e"}
	r := mustStartRotation(t, svc, "db", v.ID, consumers, defaultPolicy())

	var wg sync.WaitGroup
	for i, c := range consumers {
		wg.Add(1)
		go func(i int, c string) {
			defer wg.Done()
			_, _ = svc.Acknowledge(ctx, r.ID, c, fmt.Sprintf("req-%d", i), []byte("loaded"))
		}(i, c)
	}
	// 并发取消与激活竞争。
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.CancelRotation(ctx, r.ID, "ops")
		}()
	}
	wg.Wait()

	st, err := svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	state := st.Rotations[0].State
	if !state.Terminal() {
		t.Fatalf("rotation not in terminal state: %s", state)
	}
	// 版本状态必须与轮换终态一致。
	var vState VersionState
	for _, vi := range st.Versions {
		if vi.ID == v.ID {
			vState = vi.State
		}
	}
	switch state {
	case RotationActivated:
		if vState != VersionActive {
			t.Fatalf("rotation activated but version state = %s", vState)
		}
	case RotationCancelled:
		if vState != VersionCancelled {
			t.Fatalf("rotation cancelled but version state = %s", vState)
		}
	default:
		t.Fatalf("unexpected terminal state %s", state)
	}
}

func TestPlaintextNeverPersistedOrAudited(t *testing.T) {
	store := NewMemoryStore()
	svc, _ := newTestService(t, store)
	ctx := context.Background()
	const secret = "super-secret-plaintext"

	v := mustCreateVersion(t, svc, "db", secret)
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a"}, defaultPolicy())
	mustAck(t, svc, r.ID, "a", "req-1")
	if _, err := svc.Read(ctx, "db", v.ID, "a", "verify"); err != nil {
		t.Fatalf("Read: %v", err)
	}

	// 持久化状态中没有明文。
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%v", state), secret) {
		t.Fatal("persisted state contains plaintext")
	}
	if string(state.Versions[v.ID].Ciphertext) == secret {
		t.Fatal("ciphertext equals plaintext")
	}
	// 审计中没有明文，但包含读取记录。
	events, err := store.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	var sawRead bool
	for _, ev := range events {
		if strings.Contains(ev.Detail, secret) || strings.Contains(ev.Type, secret) {
			t.Fatalf("audit event leaks plaintext: %+v", ev)
		}
		if ev.Type == AuditSecretRead && ev.Actor == "a" {
			sawRead = true
		}
	}
	if !sawRead {
		t.Fatal("expected a secret.read audit event")
	}
}

func TestFileStorePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	svc, _ := newTestService(t, store)
	ctx := context.Background()

	v := mustCreateVersion(t, svc, "db", "persisted-secret")
	r := mustStartRotation(t, svc, "db", v.ID, []string{"a"}, defaultPolicy())
	mustAck(t, svc, r.ID, "a", "req-1")

	// 用同一个 store 重建服务，状态应完整恢复。
	svc2, err := NewService(store, testKey)
	if err != nil {
		t.Fatalf("reopen service: %v", err)
	}
	plain, err := svc2.Read(ctx, "db", v.ID, "a", "after-restart")
	if err != nil {
		t.Fatalf("Read after restart: %v", err)
	}
	if string(plain) != "persisted-secret" {
		t.Fatalf("unexpected plaintext %q", plain)
	}
	st, err := svc2.Status(ctx, "db")
	if err != nil {
		t.Fatalf("Status after restart: %v", err)
	}
	if st.ActiveVersion != v.ID {
		t.Fatalf("active version = %s, want %s", st.ActiveVersion, v.ID)
	}
}

func TestValidationAndNotFound(t *testing.T) {
	svc, _ := newTestService(t, NewMemoryStore())
	ctx := context.Background()

	if _, err := svc.CreateVersion(ctx, "", []byte("x")); !IsKind(err, KindInvalidInput) {
		t.Fatalf("empty secret id: %v", err)
	}
	if _, err := svc.CreateVersion(ctx, "db", nil); !IsKind(err, KindInvalidInput) {
		t.Fatalf("empty plaintext: %v", err)
	}
	if _, err := svc.StartRotation(ctx, "db", "ver_missing", []string{"a"}, defaultPolicy()); !IsKind(err, KindNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	if _, err := svc.Acknowledge(ctx, "rot_missing", "a", "r", nil); !IsKind(err, KindNotFound) {
		t.Fatalf("missing rotation: %v", err)
	}
	if err := svc.CancelRotation(ctx, "rot_missing", "ops"); !IsKind(err, KindNotFound) {
		t.Fatalf("cancel missing rotation: %v", err)
	}
	if _, err := svc.Read(ctx, "db", "ver_missing", "a", "r"); !IsKind(err, KindNotFound) {
		t.Fatalf("read missing version: %v", err)
	}
	if _, err := NewService(NewMemoryStore(), []byte("short")); !IsKind(err, KindInvalidInput) {
		t.Fatalf("short master key: %v", err)
	}

	// 门槛超出快照大小。
	v := mustCreateVersion(t, svc, "db", "secret")
	if _, err := svc.StartRotation(ctx, "db", v.ID, []string{"a"},
		RotationPolicy{MinAcks: 5, AckTimeout: time.Hour}); !IsKind(err, KindInvalidInput) {
		t.Fatalf("min acks out of range: %v", err)
	}
	// 同一密钥不允许并行的第二个轮换。
	mustStartRotation(t, svc, "db", v.ID, []string{"a"}, defaultPolicy())
	v2 := mustCreateVersion(t, svc, "db", "secret-2")
	if _, err := svc.StartRotation(ctx, "db", v2.ID, []string{"a"}, defaultPolicy()); !IsKind(err, KindConflict) {
		t.Fatalf("concurrent rotation: got %v, want KindConflict", err)
	}
}
