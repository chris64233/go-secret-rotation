package secretrotation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- 测试辅助：构造多版本历史 -------------------------------------------------

// rotateAndActivate 发起一次空快照轮换并立即激活，产生新版本。
func rotateAndActivate(t *testing.T, f *fixture, key, secret, reqID string) *RotationInfo {
	t.Helper()
	r, err := f.svc.StartRotation(context.Background(), StartRotationInput{
		KeyName:      key,
		NewPlaintext: []byte(secret),
		Policy:       Policy{},
		RequestID:    reqID,
	})
	if err != nil {
		t.Fatalf("start rotation: %v", err)
	}
	if _, err := f.svc.Activate(context.Background(), key, r.ID, "act-"+reqID); err != nil {
		t.Fatalf("activate rotation: %v", err)
	}
	return r
}

// --- 1. 撤销立即阻止读取 + 安全回退 -------------------------------------------

func TestRevokeActiveFallsBackToLatestSafeVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateAndActivate(t, f, "db", "v2-secret", "rot-2")

	info, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, Actor: "secops",
		Reason: "leaked in logs", FallbackToSafe: true, RequestID: "rev-1",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if info.RevokedVersion != 2 || info.FallbackVersion != 1 || info.AlreadyRevoked {
		t.Fatalf("unexpected revoke info: %+v", info)
	}

	// 默认读取立即由最近的安全历史版本 v1 接替。
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil {
		t.Fatalf("fallback read: %v", err)
	}
	if view.Version != 1 || string(view.Plaintext) != "v1-secret" || view.VersionStatus != VersionGrace {
		t.Fatalf("expected safe fallback v1, got %+v", view)
	}

	// 被撤销版本永远不能再向新请求提供：默认与显式读取都被拒绝。
	if _, err := f.svc.ReadSecret(ctx, "db", 2, "anyone"); err == nil {
		t.Fatalf("revoked version must not be readable")
	} else {
		mustCode(t, err, CodeRevoked)
	}

	st, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.ActiveVersion != 1 {
		t.Fatalf("active should point at fallback v1, got %d", st.ActiveVersion)
	}
	if st.Versions[1].Status != VersionRevoked || st.Versions[1].RevokedAt.IsZero() {
		t.Fatalf("v2 not marked revoked: %+v", st.Versions[1])
	}
	if len(st.Revocations) != 1 || st.Revocations[0].RevokedVersion != 2 ||
		st.Revocations[0].FallbackVersion != 1 {
		t.Fatalf("revocation record wrong: %+v", st.Revocations)
	}
	acts := map[string]bool{}
	for _, ev := range f.audit.Events() {
		acts[ev.Action] = true
	}
	if !acts["version_revoked"] || !acts["emergency_fallback_selected"] {
		t.Fatalf("missing revoke/fallback audits: %+v", acts)
	}
}

func TestRevokePicksMostRecentOfSeveralSafeVersions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	rotateAndActivate(t, f, "db", "v3", "rot-3")
	// v3 active；v2、v1 均处于 grace。

	info, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 3, FallbackToSafe: true,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if info.FallbackVersion != 2 {
		t.Fatalf("expected most recent safe fallback v2, got %d", info.FallbackVersion)
	}
}

func TestRevokeActiveWithoutFallbackFailsClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")

	info, err := f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 2})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if info.FallbackVersion != 0 {
		t.Fatalf("expected no fallback, got %d", info.FallbackVersion)
	}

	// 默认读取必须明确失败，而不是悄悄切到旧值。
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)

	st, _ := f.svc.Status(ctx, "db")
	if st.ActiveVersion != 0 {
		t.Fatalf("active version should be cleared, got %d", st.ActiveVersion)
	}
}

func TestRevokeWithNoSafeVersionFailsClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// 无宽限期：v1 在 v2 激活的同一刻立即退役，没有任何安全历史版本。
	f.createKey(t, "db", "v1", 0)
	rotateAndActivate(t, f, "db", "v2", "rot-2")

	info, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, FallbackToSafe: true,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if info.FallbackVersion != 0 {
		t.Fatalf("retired v1 must not be chosen as fallback, got %d", info.FallbackVersion)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)
	// 退役版本同样不会被悄悄提供。
	_, err = f.svc.ReadSecret(ctx, "db", 1, "anyone")
	mustCode(t, err, CodeExpired)
}

func TestRevokeExpiredGraceVersionIsNotChosen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Minute)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	// 推进到宽限期结束之后：v1 虽尚未被读取触发退役，但已不再安全。
	f.clock.advance(2 * time.Minute)

	info, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, FallbackToSafe: true,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if info.FallbackVersion != 0 {
		t.Fatalf("expired grace version must not be chosen, got %d", info.FallbackVersion)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)
}

func TestRevokeNonActiveVersionDoesNotChangeServing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")

	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 1}); err != nil {
		t.Fatalf("revoke grace version: %v", err)
	}
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 2 || string(view.Plaintext) != "v2" {
		t.Fatalf("active version should be unaffected: %+v %v", view, err)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 1, "anyone")
	mustCode(t, err, CodeRevoked)
}

// --- 被撤销版本永不再次激活 ---------------------------------------------------

func TestRevokePendingVersionCancelsRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("v2"),
		Policy: Policy{RequiredConsumers: []string{"svc-a"}}, RequestID: "start-2",
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	info, err := f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 2})
	if err != nil {
		t.Fatalf("revoke pending: %v", err)
	}
	if info.FallbackVersion != 0 {
		t.Fatalf("revoking pending version must not fabricate a fallback: %d", info.FallbackVersion)
	}

	// 轮换被终结，被撤销版本永远不能再激活。
	_, err = f.svc.Acknowledge(ctx, AcknowledgeInput{
		KeyName: "db", RotationID: r.ID, Consumer: "svc-a", LoadedVersion: 2,
	})
	mustCode(t, err, CodeFailedPrecondition)
	_, err = f.svc.Activate(ctx, "db", r.ID, "")
	mustCode(t, err, CodeFailedPrecondition)
	_, err = f.svc.ReadSecret(ctx, "db", 2, "anyone")
	mustCode(t, err, CodeRevoked)

	st, _ := f.svc.Status(ctx, "db")
	if st.PendingRotationID != "" {
		t.Fatalf("pending rotation should be cleared, got %s", st.PendingRotationID)
	}
	if st.ActiveVersion != 1 {
		t.Fatalf("original active version should remain, got %d", st.ActiveVersion)
	}

	// 撤销待激活版本后，可以发起并完成新的轮换恢复服务。
	r2, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("v3"), Policy: Policy{}, RequestID: "start-3",
	})
	if err != nil {
		t.Fatalf("start recovery rotation: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "db", r2.ID, ""); err != nil {
		t.Fatalf("activate recovery: %v", err)
	}
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 3 || string(view.Plaintext) != "v3" {
		t.Fatalf("service did not recover via new rotation: %+v %v", view, err)
	}
}

func TestFailClosedRecoversViaNewRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 2}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)

	rotateAndActivate(t, f, "db", "v3", "rot-3")
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 3 {
		t.Fatalf("expected recovery to v3, got %+v %v", view, err)
	}
}

func TestNewActivationDoesNotExtendFallbackGrace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, FallbackToSafe: true,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	st, _ := f.store.Get(ctx, "db")
	originalRetire := st.Versions[0].RetireAt

	// 临时接替期间完成新轮换：v1 只是退出“在用”，宽限期截止时刻不变。
	rotateAndActivate(t, f, "db", "v3", "rot-3")
	st, _ = f.store.Get(ctx, "db")
	if st.ActiveVersion != 3 {
		t.Fatalf("active = %d, want 3", st.ActiveVersion)
	}
	if !st.Versions[0].RetireAt.Equal(originalRetire) || st.Versions[0].Status != VersionGrace {
		t.Fatalf("fallback grace deadline was altered: %+v", st.Versions[0])
	}
}

// --- 2. 接替版本到期：停止提供，不自行切换 ------------------------------------

func TestFallbackExpiryStopsServingWithoutSwitching(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 30*time.Minute)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	rotateAndActivate(t, f, "db", "v3", "rot-3")
	// v3 active，v2、v1 处于 grace。撤销 v3，最近的 v2 临时接替。
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 3, FallbackToSafe: true,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 2 {
		t.Fatalf("expected fallback v2, got %+v %v", view, err)
	}

	// 推进到所有 grace 版本到期之后。
	f.clock.advance(time.Hour)
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)

	// 接替版本已退役、active 清零；服务不会自行切到更老的 v1。
	st, _ := f.store.Get(ctx, "db")
	if st.ActiveVersion != 0 {
		t.Fatalf("active must be cleared after fallback expiry, got %d", st.ActiveVersion)
	}
	if st.Versions[1].Status != VersionRetired {
		t.Fatalf("expired fallback v2 should be retired, got %s", st.Versions[1].Status)
	}
	// 此后每次默认读取都失败，状态保持稳定。
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)
}

// --- 2. 读取与撤销并发：解密窗口内被撤销绝不交付 --------------------------------

// gatedEncryptor 在 Decrypt 指定版本时阻塞，直到测试关闭 release，
// 用于确定性地把“撤销”插入到一次读取的解密窗口中。
type gatedEncryptor struct {
	Encryptor
	gateVersion int
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
}

func newGatedEncryptor(inner Encryptor, gateVersion int) *gatedEncryptor {
	return &gatedEncryptor{
		Encryptor:   inner,
		gateVersion: gateVersion,
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (g *gatedEncryptor) Decrypt(ctx context.Context, keyName string, version int, blob []byte) ([]byte, error) {
	if version == g.gateVersion {
		g.enterOnce.Do(func() { close(g.entered) })
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g.Encryptor.Decrypt(ctx, keyName, version, blob)
}

func TestReadDuringRevokeWindowNeverDeliversRevokedVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateAndActivate(t, f, "db", "v2-secret", "rot-2")

	gate := newGatedEncryptor(f.enc, 2)
	f.svc.cipher = gate

	readErr := make(chan error, 1)
	readView := make(chan *SecretView, 1)
	go func() {
		v, e := f.svc.ReadSecret(ctx, "db", 0, "anyone")
		readView <- v
		readErr <- e
	}()

	// 等待读取进入 v2 的解密，然后在其解密窗口内完成撤销（v1 安全接替）。
	<-gate.entered
	info, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, FallbackToSafe: true,
	})
	if err != nil || info.FallbackVersion != 1 {
		t.Fatalf("revoke during read window: %+v %v", info, err)
	}
	close(gate.release)

	if err := <-readErr; err != nil {
		t.Fatalf("read should retarget to safe fallback, got error: %v", err)
	}
	view := <-readView
	// 解密得到的 v2 明文必须被复核逻辑丢弃：读取只能交付撤销后的安全版本 v1。
	if view.Version != 1 || string(view.Plaintext) != "v1-secret" {
		t.Fatalf("read delivered revoked/other version after revocation committed during decrypt: %+v", view)
	}

	// 撤销提交后，任何后续读取都不可能再得到 v2。
	for i := 0; i < 5; i++ {
		v, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
		if err != nil {
			t.Fatalf("post-revoke read %d: %v", i, err)
		}
		if v.Version == 2 {
			t.Fatalf("post-revoke read %d delivered revoked v2", i)
		}
	}
}

func TestConcurrentReadsAndRevoke(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateAndActivate(t, f, "db", "v2-secret", "rot-2")

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var served []int
	var failCodes []Code

	// 一半读者在撤销前后持续读取；撤销只发生一次。
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failCodes = append(failCodes, ErrorCode(err))
				return
			}
			served = append(served, v.Version)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, _ = f.svc.RevokeSecret(ctx, RevokeInput{
			KeyName: "db", Version: 2, FallbackToSafe: true,
		})
	}()
	close(start)
	wg.Wait()

	// 撤销完成后再读，绝不可能得到 v2。
	v, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil {
		t.Fatalf("final read: %v", err)
	}
	if v.Version != 1 {
		t.Fatalf("after revoke settles, only safe fallback v1 may be served, got v%d", v.Version)
	}
	// 任何失败都只能是明确的失败类别，不允许出现内部错误。
	for _, c := range failCodes {
		if c != CodeRevoked && c != CodeUnavailable && c != CodeExpired {
			t.Fatalf("unexpected failure code during race: %s", c)
		}
	}
}

func TestRevokingFallbackChainsToEarlierSafeVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	rotateAndActivate(t, f, "db", "v3", "rot-3")

	// 撤销 v3 -> v2 接替；再撤销 v2 -> 只能回退到仍安全的 v1。
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 3, FallbackToSafe: true,
	}); err != nil {
		t.Fatalf("revoke v3: %v", err)
	}
	info, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, FallbackToSafe: true,
	})
	if err != nil {
		t.Fatalf("revoke v2: %v", err)
	}
	if info.FallbackVersion != 1 {
		t.Fatalf("expected chain fallback to v1, got %d", info.FallbackVersion)
	}
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 1 || string(view.Plaintext) != "v1" {
		t.Fatalf("expected v1 serving, got %+v %v", view, err)
	}

	// 再撤销最后的 v1：无安全版本，fail-closed。
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 1, FallbackToSafe: true,
	}); err != nil {
		t.Fatalf("revoke v1: %v", err)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeUnavailable)
}

// --- 3. 重复撤销幂等 + 记录原子保存 + 机密性 ------------------------------------

func TestRevokeIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")

	in := RevokeInput{
		KeyName: "db", Version: 2, Actor: "secops",
		FallbackToSafe: true, RequestID: "rev-1",
	}
	first, err := f.svc.RevokeSecret(ctx, in)
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if first.AlreadyRevoked {
		t.Fatalf("first revoke should not be flagged as replay")
	}
	second, err := f.svc.RevokeSecret(ctx, in)
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if !second.AlreadyRevoked || second.FallbackVersion != 1 {
		t.Fatalf("replay should be idempotent: %+v", second)
	}
	// 不带请求号重复撤销同一版本同样幂等。
	third, err := f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 2})
	if err != nil || !third.AlreadyRevoked {
		t.Fatalf("bare replay should be idempotent: %+v %v", third, err)
	}

	st, _ := f.store.Get(ctx, "db")
	if len(st.Revocations) != 1 {
		t.Fatalf("idempotent revoke appended duplicate record: %d", len(st.Revocations))
	}
	if got := len(f.audit.EventsByAction("version_revoked")); got != 1 {
		t.Fatalf("idempotent revoke audited %d times, want 1", got)
	}
	if got := len(f.audit.EventsByAction("emergency_fallback_selected")); got != 1 {
		t.Fatalf("idempotent revoke re-selected fallback %d times", got)
	}
}

func TestRevokeRequestIDConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")
	rotateAndActivate(t, f, "db", "v3", "rot-3")

	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, RequestID: "rev-shared",
	}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// 同一请求号用于撤销不同版本 -> 冲突。
	_, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 3, RequestID: "rev-shared",
	})
	mustCode(t, err, CodeConflict)
	// 冲突不得污染幂等记录：v3 仍未撤销，且该请求号仍可用于重放 v2。
	st, _ := f.store.Get(ctx, "db")
	if st.Versions[2].Status == VersionRevoked {
		t.Fatalf("conflicting revoke must not revoke v3")
	}
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, RequestID: "rev-shared",
	}); err != nil {
		t.Fatalf("original request replay should succeed: %v", err)
	}
}

func TestRevokeValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", 0)

	_, err := f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "", Version: 1})
	mustCode(t, err, CodeInvalidArgument)
	_, err = f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 0})
	mustCode(t, err, CodeInvalidArgument)
	_, err = f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "db", Version: 99})
	mustCode(t, err, CodeNotFound)
	_, err = f.svc.RevokeSecret(ctx, RevokeInput{KeyName: "missing", Version: 1})
	mustCode(t, err, CodeNotFound)
}

// 状态变更与撤销记录在同一次 CAS 原子落库：读取持久化状态时二者必然同时可见。
func TestRevokeStateAndRecordAtomic(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1", time.Hour)
	rotateAndActivate(t, f, "db", "v2", "rot-2")

	before, _ := f.store.Get(ctx, "db")
	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, FallbackToSafe: true, RequestID: "rev-1",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	after, _ := f.store.Get(ctx, "db")

	// 单次原子写入：修订号恰好 +1，且撤销状态、记录、幂等键一并可见。
	if after.Revision != before.Revision+1 {
		t.Fatalf("revoke should be one atomic write, revision %d -> %d",
			before.Revision, after.Revision)
	}
	if after.Versions[1].Status != VersionRevoked {
		t.Fatalf("version status not persisted atomically")
	}
	if len(after.Revocations) != 1 || after.RevokeRequests["rev-1"] != 2 {
		t.Fatalf("record/idempotency key not persisted atomically: rec=%d map=%v",
			len(after.Revocations), after.RevokeRequests)
	}
}

func TestRevokeDoesNotLeakPlaintext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := "REVOKE-PROBE-密钥"
	f.createKey(t, "db", secret, time.Hour)
	rotateAndActivate(t, f, "db", secret+"-v2", "rot-2")

	if _, err := f.svc.RevokeSecret(ctx, RevokeInput{
		KeyName: "db", Version: 2, Actor: "secops",
		Reason: "non-sensitive reason", FallbackToSafe: true,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// 撤销后读取被撤销版本的错误也不得携带明文。
	_, err := f.svc.ReadSecret(ctx, "db", 2, "anyone")
	if err == nil {
		t.Fatalf("expected revoke error")
	}

	st, _ := f.store.Get(ctx, "db")
	dump := fmt.Sprintf("%+v", st)
	for _, probe := range []string{secret, secret + "-v2"} {
		if strings.Contains(dump, probe) {
			t.Fatalf("plaintext leaked into persisted revocation state: %q", probe)
		}
	}
	for _, ev := range f.audit.Events() {
		if strings.Contains(fmt.Sprintf("%+v", ev), secret) {
			t.Fatalf("plaintext leaked into revocation audit: %+v", ev)
		}
		if strings.Contains(ev.Detail, secret) || strings.Contains(ev.Actor, secret) {
			t.Fatalf("plaintext leaked into audit metadata")
		}
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("plaintext leaked into revoke/read error: %v", err)
	}
}
