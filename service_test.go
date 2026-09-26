package secretrotation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- 测试夹具 ---------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	svc   *Service
	store *MemoryStore
	enc   *AESGCMEncryptor
	audit *MemoryAuditSink
	clock *fakeClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	enc, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("new encryptor: %v", err)
	}
	store := NewMemoryStore()
	audit := NewMemoryAuditSink()
	clk := newFakeClock()
	return &fixture{
		svc:   NewService(store, enc, audit, clk.now),
		store: store,
		enc:   enc,
		audit: audit,
		clock: clk,
	}
}

func (f *fixture) createKey(t *testing.T, name string, plaintext string, grace time.Duration, readers ...string) {
	t.Helper()
	_, err := f.svc.CreateKeyVersion(context.Background(), CreateKeyInput{
		Name:        name,
		Plaintext:   []byte(plaintext),
		GracePeriod: grace,
		Readers:     readers,
	})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
}

func mustCode(t *testing.T, err error, want Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error code %s, got nil", want)
	}
	if got := ErrorCode(err); got != want {
		t.Fatalf("want error code %s, got %s (%v)", want, got, err)
	}
}

// --- 版本创建与受控读取 ------------------------------------------------------

func TestCreateKeyAndControlledRead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Minute, "svc-a")

	view, err := f.svc.ReadSecret(ctx, "db", 0, "svc-a")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if view.Version != 1 || string(view.Plaintext) != "v1-secret" || view.VersionStatus != VersionActive {
		t.Fatalf("unexpected view: %+v", view)
	}

	// 非白名单消费者读取必须被拒绝。
	_, err = f.svc.ReadSecret(ctx, "db", 0, "svc-b")
	mustCode(t, err, CodePermissionDenied)

	// 读取不存在的密钥/版本。
	_, err = f.svc.ReadSecret(ctx, "missing", 0, "svc-a")
	mustCode(t, err, CodeNotFound)
	_, err = f.svc.ReadSecret(ctx, "db", 99, "svc-a")
	mustCode(t, err, CodeNotFound)
}

func TestCreateKeyValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	_, err := f.svc.CreateKeyVersion(ctx, CreateKeyInput{Name: "", Plaintext: []byte("x")})
	mustCode(t, err, CodeInvalidArgument)
	_, err = f.svc.CreateKeyVersion(ctx, CreateKeyInput{Name: "k", Plaintext: nil})
	mustCode(t, err, CodeInvalidArgument)
	_, err = f.svc.CreateKeyVersion(ctx, CreateKeyInput{Name: "k", Plaintext: []byte("x"), GracePeriod: -1})
	mustCode(t, err, CodeInvalidArgument)
	_, err = f.svc.CreateKeyVersion(ctx, CreateKeyInput{Name: "k", Plaintext: []byte("x"), Readers: []string{"a", "a"}})
	mustCode(t, err, CodeInvalidArgument)

	f.createKey(t, "dup", "x", 0)
	_, err = f.svc.CreateKeyVersion(ctx, CreateKeyInput{Name: "dup", Plaintext: []byte("y")})
	mustCode(t, err, CodeAlreadyExists)
}

// --- 轮换与确认 -------------------------------------------------------------

func startTestRotation(t *testing.T, f *fixture, consumers []string, timeout time.Duration, newSecret string) *RotationInfo {
	t.Helper()
	r, err := f.svc.StartRotation(context.Background(), StartRotationInput{
		KeyName:      "db",
		NewPlaintext: []byte(newSecret),
		Policy:       Policy{RequiredConsumers: consumers, Timeout: timeout},
		RequestID:    "start-1",
	})
	if err != nil {
		t.Fatalf("start rotation: %v", err)
	}
	return r
}

func TestRotationFullLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", 30*time.Minute)
	r := startTestRotation(t, f, []string{"svc-a", "svc-b"}, time.Hour, "v2-secret")

	if r.Status != RotationPending || r.PendingVersion != 2 {
		t.Fatalf("unexpected rotation: %+v", r)
	}
	if len(r.RequiredConsumers) != 2 || r.RequiredConsumers[0] != "svc-a" {
		t.Fatalf("snapshot not frozen as sorted copy: %+v", r.RequiredConsumers)
	}

	// 门槛未达成不能激活。
	_, err := f.svc.Activate(ctx, "db", r.ID, "act-1")
	mustCode(t, err, CodeFailedPrecondition)

	// svc-a 确认，仍然不够。
	if _, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 2, RequestID: "ack-a",
	}); err != nil {
		t.Fatalf("ack a: %v", err)
	}
	_, err = f.svc.Activate(ctx, "db", r.ID, "act-1")
	mustCode(t, err, CodeFailedPrecondition)

	// svc-b 确认后门槛达成，原子激活。
	if _, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-b", LoadedVersion: 2, RequestID: "ack-b",
	}); err != nil {
		t.Fatalf("ack b: %v", err)
	}
	got, err := f.svc.Activate(ctx, "db", r.ID, "act-1")
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if got.Status != RotationActivated {
		t.Fatalf("status = %s", got.Status)
	}

	// 新版本可读且为 v2；旧版本处于 grace 且仍可读。
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil {
		t.Fatalf("read active: %v", err)
	}
	if view.Version != 2 || string(view.Plaintext) != "v2-secret" {
		t.Fatalf("active version wrong: %+v", view)
	}
	old, err := f.svc.ReadSecret(ctx, "db", 1, "anyone")
	if err != nil {
		t.Fatalf("read grace version: %v", err)
	}
	if old.VersionStatus != VersionGrace || string(old.Plaintext) != "v1-secret" {
		t.Fatalf("grace view wrong: %+v", old)
	}
}

func TestAcknowledgeIdempotentAndConflicts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)
	r := startTestRotation(t, f, []string{"svc-a", "svc-b"}, time.Hour, "v2")

	ack := func(consumer string, version int, reqID string) error {
		_, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
			KeyName: "db", RotationID: r.ID, Consumer: consumer,
			LoadedVersion: version, RequestID: reqID,
		})
		return err
	}

	if err := ack("svc-a", 2, "req-1"); err != nil {
		t.Fatalf("first ack: %v", err)
	}
	// 相同消费者+轮换重复确认：幂等成功，不重复计数。
	if err := ack("svc-a", 2, "req-1"); err != nil {
		t.Fatalf("duplicate ack should be idempotent: %v", err)
	}
	if err := ack("svc-a", 2, "req-1-retry"); err != nil {
		t.Fatalf("duplicate ack with new request id should still be idempotent: %v", err)
	}
	st, _ := f.store.Get(ctx, "db")
	rot := findRotation(st, r.ID)
	if len(rot.Acks) != 1 {
		t.Fatalf("duplicate ack advanced state: acks=%v", rot.Acks)
	}

	// 同一请求号提交不同内容（换消费者）-> 冲突。
	mustCode(t, ack("svc-b", 2, "req-1"), CodeConflict)
}

func TestAcknowledgeContentConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)
	r := startTestRotation(t, f, []string{"svc-a", "svc-b"}, time.Hour, "v2")

	ack := func(consumer string, version int, reqID string) error {
		_, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
			KeyName: "db", RotationID: r.ID, Consumer: consumer,
			LoadedVersion: version, RequestID: reqID,
		})
		return err
	}
	if err := ack("svc-a", 2, "req-2"); err != nil {
		t.Fatalf("first ack: %v", err)
	}
	// 同请求号、同消费者、不同加载版本 -> 冲突。
	mustCode(t, ack("svc-a", 1, "req-2"), CodeConflict)
	// 同请求号、不同消费者 -> 冲突。
	mustCode(t, ack("svc-b", 2, "req-2"), CodeConflict)
}

func TestAcknowledgeNonMemberAndWrongVersionAndLate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)
	r := startTestRotation(t, f, []string{"svc-a"}, time.Hour, "v2")

	// 非快照成员不能确认，且其确认不计数。
	_, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-late-joiner", LoadedVersion: 2,
	})
	mustCode(t, err, CodePermissionDenied)

	// 加载版本不匹配。
	_, err = f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 1,
	})
	mustCode(t, err, CodeInvalidArgument)

	// 正常确认并激活。
	if _, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 2,
	}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "db", r.ID, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// 终态之后的迟到确认不能推进状态。
	_, err = f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 2,
	})
	mustCode(t, err, CodeFailedPrecondition)
}

func TestFrozenSnapshotDoesNotMoveThreshold(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)
	// 发起后即便外部“消费者目录”新增了成员，门槛仍是快照中的两个。
	r := startTestRotation(t, f, []string{"svc-a", "svc-b"}, 0, "v2")

	for _, c := range []string{"svc-new-1", "svc-new-2", "svc-new-3"} {
		_, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
			KeyName: "db", RotationID: r.ID, Consumer: c, LoadedVersion: 2,
		})
		mustCode(t, err, CodePermissionDenied)
	}
	// 新成员再多也不影响：快照两人确认即可激活。
	for _, c := range []string{"svc-a", "svc-b"} {
		if _, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
			KeyName: "db", RotationID: r.ID, Consumer: c, LoadedVersion: 2,
		}); err != nil {
			t.Fatalf("ack %s: %v", c, err)
		}
	}
	if _, err := f.svc.Activate(ctx, "db", r.ID, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func TestStartRotationIdempotency(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)

	in := StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("v2"),
		Policy:    Policy{RequiredConsumers: []string{"svc-a"}, Timeout: time.Hour},
		RequestID: "start-1",
	}
	first, err := f.svc.StartRotation(ctx, in)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// 同请求号重放：返回同一轮换。
	replay, err := f.svc.StartRotation(ctx, in)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("idempotent replay created new rotation: %s vs %s", replay.ID, first.ID)
	}
	// 同请求号但参数不同 -> 冲突。
	in.Policy.RequiredConsumers = []string{"svc-a", "svc-b"}
	_, err = f.svc.StartRotation(ctx, in)
	mustCode(t, err, CodeConflict)

	// 已有进行中的轮换时，换请求号发起 -> 失败。
	in.RequestID = "start-2"
	_, err = f.svc.StartRotation(ctx, in)
	mustCode(t, err, CodeFailedPrecondition)
}

// --- 终态竞争：激活 / 取消 / 超时 只能产生一个终态 ----------------------------

func TestTerminalRaceActivateVsCancel(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", 0)
	// 空快照：发起后立即满足激活条件，激活与取消直接竞争。
	r := startTestRotation(t, f, nil, 0, "v2-secret")

	const n = 24
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = f.svc.Activate(ctx, "db", r.ID, fmt.Sprintf("act-%d", i))
			} else {
				_, _ = f.svc.Cancel(ctx, "db", r.ID, fmt.Sprintf("can-%d", i))
			}
		}(i)
	}
	wg.Wait()

	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var final *RotationInfo
	for i := range info.Rotations {
		if info.Rotations[i].ID == r.ID {
			final = &info.Rotations[i]
		}
	}
	if final == nil || !final.Status.isTerminal() {
		t.Fatalf("rotation not in exactly one terminal state: %+v", final)
	}
	if info.PendingRotationID != "" {
		t.Fatalf("pending rotation should be cleared, got %s", info.PendingRotationID)
	}
	// 终态迁移审计事件必须恰好一条：激活与取消各只有一次真正落库。
	activations := f.audit.EventsByAction("rotation_activated")
	cancellations := f.audit.EventsByAction("rotation_cancelled")
	if len(activations)+len(cancellations) != 1 {
		t.Fatalf("expected exactly one terminal transition, got activated=%d cancelled=%d",
			len(activations), len(cancellations))
	}

	switch final.Status {
	case RotationActivated:
		// 激活胜出：新版本在用，迟到取消必须被拒绝。
		if info.ActiveVersion != 2 {
			t.Fatalf("active version = %d, want 2", info.ActiveVersion)
		}
		_, err := f.svc.Cancel(ctx, "db", r.ID, "late-cancel")
		mustCode(t, err, CodeFailedPrecondition)
		view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
		if err != nil || string(view.Plaintext) != "v2-secret" {
			t.Fatalf("post-race read wrong: %+v err=%v", view, err)
		}
	case RotationCancelled:
		// 取消胜出：旧版本仍在用，待激活版本废弃，重复取消幂等。
		if info.ActiveVersion != 1 {
			t.Fatalf("active version = %d, want 1", info.ActiveVersion)
		}
		if info.Versions[1].Status != VersionRetired {
			t.Fatalf("pending version should be retired, got %s", info.Versions[1].Status)
		}
		again, err := f.svc.Cancel(ctx, "db", r.ID, "can-again")
		if err != nil || again.Status != RotationCancelled {
			t.Fatalf("idempotent cancel failed: %+v %v", again, err)
		}
		_, err = f.svc.Activate(ctx, "db", r.ID, "late-activate")
		mustCode(t, err, CodeFailedPrecondition)
	}
}

func TestTerminalRaceIncludesTimeout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", 0)
	r := startTestRotation(t, f, nil, time.Hour, "v2-secret")
	// 推进到截止时间之后，使超时也具备终结资格，三者同时竞争。
	f.clock.advance(2 * time.Hour)

	const n = 30
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				_, _ = f.svc.Activate(ctx, "db", r.ID, fmt.Sprintf("act-%d", i))
			case 1:
				_, _ = f.svc.Cancel(ctx, "db", r.ID, fmt.Sprintf("can-%d", i))
			default:
				_, _ = f.svc.ProcessTimeout(ctx, "db")
			}
		}(i)
	}
	wg.Wait()

	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !info.Rotations[0].Status.isTerminal() {
		t.Fatalf("rotation not terminal: %s", info.Rotations[0].Status)
	}
	if info.PendingRotationID != "" {
		t.Fatalf("pending rotation not cleared: %s", info.PendingRotationID)
	}
	// 三类终态迁移审计加起来必须恰好一条。
	transitions := len(f.audit.EventsByAction("rotation_activated")) +
		len(f.audit.EventsByAction("rotation_cancelled")) +
		len(f.audit.EventsByAction("rotation_timed_out"))
	if transitions != 1 {
		t.Fatalf("expected exactly one terminal transition, got %d", transitions)
	}
	// 再跑一次超时扫描：不得产生第二个终态/重复审计。
	if _, err := f.svc.ProcessTimeout(ctx, "db"); err != nil {
		t.Fatalf("idempotent timeout re-run: %v", err)
	}
	if got := len(f.audit.EventsByAction("rotation_timed_out")); got > 1 {
		t.Fatalf("timeout audited %d times, want at most 1", got)
	}
}

// --- 超时 -------------------------------------------------------------------

func TestProcessTimeout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)
	startTestRotation(t, f, []string{"svc-a"}, time.Minute, "v2")

	// 未到截止时间：什么都不发生。
	if info, err := f.svc.ProcessTimeout(ctx, "db"); err != nil || info != nil {
		t.Fatalf("early timeout: info=%+v err=%v", info, err)
	}

	f.clock.advance(time.Minute + time.Second)
	info, err := f.svc.ProcessTimeout(ctx, "db")
	if err != nil {
		t.Fatalf("process timeout: %v", err)
	}
	if info == nil || info.Status != RotationTimedOut {
		t.Fatalf("want timed out, got %+v", info)
	}

	st, _ := f.store.Get(ctx, "db")
	if st.PendingRotation != "" {
		t.Fatalf("pending rotation not cleared")
	}
	if st.Versions[1].Status != VersionRetired {
		t.Fatalf("pending version should be retired, got %s", st.Versions[1].Status)
	}
	// pending 版本永远不可读。
	_, err = f.svc.ReadSecret(ctx, "db", 2, "anyone")
	mustCode(t, err, CodeExpired)
	// 超时后允许发起新轮换。
	r2, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("v3"),
		Policy:    Policy{},
		RequestID: "start-2",
	})
	if err != nil {
		t.Fatalf("start after timeout: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "db", r2.ID, ""); err != nil {
		t.Fatalf("activate next rotation: %v", err)
	}
}

func TestSweepTimeouts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "k1", "a", 0)
	f.createKey(t, "k2", "b", 0)
	r1, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "k1", NewPlaintext: []byte("a2"),
		Policy: Policy{Timeout: time.Minute},
	})
	if err != nil {
		t.Fatalf("start k1: %v", err)
	}
	if _, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "k2", NewPlaintext: []byte("b2"),
		Policy: Policy{Timeout: time.Hour},
	}); err != nil {
		t.Fatalf("start k2: %v", err)
	}
	f.clock.advance(2 * time.Minute)

	done, err := f.svc.SweepTimeouts(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(done) != 1 || done[0].ID != r1.ID || done[0].Status != RotationTimedOut {
		t.Fatalf("sweep result wrong: %+v", done)
	}
}

// --- 宽限期结束后旧版本读取必须失败 --------------------------------------------

func TestGracePeriodExpiryForcesReadFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Minute)
	r := startTestRotation(t, f, nil, 0, "v2-secret")
	if _, err := f.svc.Activate(ctx, "db", r.ID, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}

	// 宽限期内旧版本仍可读。
	old, err := f.svc.ReadSecret(ctx, "db", 1, "anyone")
	if err != nil || string(old.Plaintext) != "v1-secret" {
		t.Fatalf("grace read: %+v %v", old, err)
	}

	f.clock.advance(time.Minute + time.Second)
	// 第一次过期读取：原子退役并报过期。
	_, err = f.svc.ReadSecret(ctx, "db", 1, "anyone")
	mustCode(t, err, CodeExpired)
	// 退役已持久化：此后每次读取都失败，即使时钟不再变化。
	_, err = f.svc.ReadSecret(ctx, "db", 1, "anyone")
	mustCode(t, err, CodeExpired)

	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if info.Versions[0].Status != VersionRetired {
		t.Fatalf("old version status = %s, want retired", info.Versions[0].Status)
	}
	// 新版本不受影响。
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 2 || string(view.Plaintext) != "v2-secret" {
		t.Fatalf("active read after grace: %+v %v", view, err)
	}
}

func TestZeroGraceRetiresImmediately(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", 0)
	r := startTestRotation(t, f, nil, 0, "v2-secret")
	if _, err := f.svc.Activate(ctx, "db", r.ID, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}
	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if info.Versions[0].Status != VersionRetired {
		t.Fatalf("old version should be immediately retired, got %s", info.Versions[0].Status)
	}
	// 无宽限期：激活同一刻退役，第一次读取即失败。
	_, err = f.svc.ReadSecret(ctx, "db", 1, "anyone")
	mustCode(t, err, CodeExpired)
}

// --- 静态加密：持久化、审计、错误均不得泄漏明文 --------------------------------

func TestPlaintextNeverLeakedToStorageOrAudit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := string([]byte{0xAB}) + "PLAINTEXT-PROBE-密钥"
	f.createKey(t, "db", secret, time.Minute)
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName:      "db",
		NewPlaintext: []byte(secret + "-v2"),
		Policy:       Policy{RequiredConsumers: []string{"svc-a"}},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 2,
	}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "db", r.ID, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := f.svc.ReadSecret(ctx, "db", 1, "anyone"); err != nil {
		t.Fatalf("grace read: %v", err)
	}
	f.clock.advance(2 * time.Minute)
	if _, err := f.svc.ReadSecret(ctx, "db", 1, "anyone"); err == nil {
		t.Fatalf("expected expiry error")
	}

	st, err := f.store.Get(ctx, "db")
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	dump := fmt.Sprintf("%+v", st)
	for _, probe := range []string{secret, secret + "-v2"} {
		if strings.Contains(dump, probe) {
			t.Fatalf("plaintext leaked into persisted state: %q", probe)
		}
	}
	// 密文必须确实存在且不等于明文。
	if len(st.Versions[0].Ciphertext) == 0 {
		t.Fatalf("ciphertext missing")
	}
	if string(st.Versions[0].Ciphertext) == secret {
		t.Fatalf("ciphertext is identical to plaintext")
	}

	for _, ev := range f.audit.Events() {
		blob := fmt.Sprintf("%+v", ev)
		if strings.Contains(blob, secret) {
			t.Fatalf("plaintext leaked into audit event: %+v", ev)
		}
	}
}

func TestErrorsDoNotLeakPlaintext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := "SUPERSECRET-PROBE"
	f.createKey(t, "db", secret, 0)
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName:      "db",
		NewPlaintext: []byte(secret + "-2"),
		Policy:       Policy{RequiredConsumers: []string{"svc-a"}, Timeout: time.Nanosecond},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// 制造各类错误，检查错误文本不含明文片段。
	probeErrs := []error{}
	_, e1 := f.svc.Acknowledge(ctx, AcknowledgeInput{KeyName: "db", RotationID: r.ID, Consumer: "x", LoadedVersion: 2})
	probeErrs = append(probeErrs, e1)
	_, e2 := f.svc.ReadSecret(ctx, "db", 2, "anyone") // pending 版本
	probeErrs = append(probeErrs, e2)
	_, e3 := f.svc.ReadSecret(ctx, "db", 5, "anyone")
	probeErrs = append(probeErrs, e3)
	_, e4 := f.svc.Activate(ctx, "db", "rot-missing", "")
	probeErrs = append(probeErrs, e4)
	// 解密失败：篡改密文。
	st, _ := f.store.Get(ctx, "db")
	st.Versions[0].Ciphertext[len(st.Versions[0].Ciphertext)-1] ^= 0xFF
	if err := f.store.CompareAndSwap(ctx, mustRevision(t, f, "db"), st); err != nil {
		t.Fatalf("tamper cas: %v", err)
	}
	_, e5 := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	probeErrs = append(probeErrs, e5)

	for _, e := range probeErrs {
		if e == nil {
			continue
		}
		if strings.Contains(e.Error(), secret) {
			t.Fatalf("plaintext leaked in error: %v", e)
		}
	}
	mustCode(t, e5, CodeInternal)
}

func mustRevision(t *testing.T, f *fixture, name string) *KeyState {
	t.Helper()
	st, err := f.store.Get(context.Background(), name)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return st
}

// --- 加密器单元测试 -----------------------------------------------------------

func TestAESGCMRoundTripAndTamper(t *testing.T) {
	enc, err := NewAESGCMEncryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()

	ct1, err := enc.Encrypt(ctx, "db", 1, []byte("same-plaintext"))
	if err != nil {
		t.Fatalf("enc1: %v", err)
	}
	ct2, err := enc.Encrypt(ctx, "db", 1, []byte("same-plaintext"))
	if err != nil {
		t.Fatalf("enc2: %v", err)
	}
	if string(ct1) == string(ct2) {
		t.Fatalf("identical plaintext must yield different ciphertext (random nonce)")
	}
	pt, err := enc.Decrypt(ctx, "db", 1, ct1)
	if err != nil || string(pt) != "same-plaintext" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	// 版本 AAD 绑定：挪到别的版本/密钥应认证失败。
	if _, err := enc.Decrypt(ctx, "db", 2, ct1); err == nil {
		t.Fatalf("cross-version ciphertext swap must fail")
	}
	if _, err := enc.Decrypt(ctx, "other", 1, ct1); err == nil {
		t.Fatalf("cross-key ciphertext swap must fail")
	}
	// 篡改密文应认证失败。
	bad := append([]byte(nil), ct1...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := enc.Decrypt(ctx, "db", 1, bad); err == nil {
		t.Fatalf("tampered ciphertext must fail")
	}
	// 非法主密钥长度。
	if _, err := NewAESGCMEncryptor(make([]byte, 7)); err == nil {
		t.Fatalf("invalid KEK length must fail")
	}
}

// --- 状态查询与审计 -----------------------------------------------------------

func TestStatusAndAudit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "STATUSPROBE-one", 2*time.Minute)
	r := startTestRotation(t, f, []string{"svc-a"}, time.Hour, "STATUSPROBE-two")

	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if info.ActiveVersion != 1 || info.PendingRotationID != r.ID || len(info.Versions) != 2 {
		t.Fatalf("unexpected status: %+v", info)
	}
	if info.Versions[1].Status != VersionPending {
		t.Fatalf("new version should be pending, got %s", info.Versions[1].Status)
	}
	// 状态视图不得携带密钥材料：VersionInfo 无密文字段（编译期保证），
	// 其文本形式也不应出现明文探测串。
	if strings.Contains(fmt.Sprintf("%+v", info), "STATUSPROBE") {
		t.Fatalf("status payload leaked secret material: %+v", info)
	}

	if _, err := f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 2,
	}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "db", r.ID, "act"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := f.svc.ReadSecret(ctx, "db", 0, "anyone"); err != nil {
		t.Fatalf("read active: %v", err)
	}
	if _, err := f.svc.ReadSecret(ctx, "db", 1, "anyone"); err != nil {
		t.Fatalf("read grace version: %v", err)
	}
	actions := map[string]bool{}
	for _, ev := range f.audit.Events() {
		actions[ev.Action] = true
	}
	for _, want := range []string{"key_created", "rotation_started", "acknowledged", "rotation_activated", "version_grace_started", "secret_read"} {
		if !actions[want] {
			t.Fatalf("audit action %q missing, got %+v", want, actions)
		}
	}
}

func TestErrorCodeHelpers(t *testing.T) {
	mustCode(t, errors.New("raw"), CodeInternal)
	var e *Error
	if !errors.As(fmt.Errorf("wrap: %w", newError(CodeNotFound, "op", "x")), &e) || e.Code != CodeNotFound {
		t.Fatalf("errors.As classification failed")
	}
}
