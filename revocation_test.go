package secretrotation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// rotateToN 通过一次空快照轮换把密钥推进到第 n 个版本（测试辅助）。
func rotateToN(t *testing.T, f *fixture, keyName string, n int, secret string) *RotationInfo {
	t.Helper()
	ctx := context.Background()
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName:      keyName,
		NewPlaintext: []byte(secret),
		Policy:       Policy{},
		RequestID:    fmt.Sprintf("start-v%d", n),
	})
	if err != nil {
		t.Fatalf("start v%d: %v", n, err)
	}
	if _, err := f.svc.Activate(ctx, keyName, r.ID, fmt.Sprintf("act-v%d", n)); err != nil {
		t.Fatalf("activate v%d: %v", n, err)
	}
	return r
}

// --- 撤销当前版本并由历史安全版本接替 ------------------------------------------

func TestRevokeActiveFallsBackToLatestSafeGraceVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")
	rotateToN(t, f, "db", 3, "v3-secret")

	// v3 active；v2、v1 均在 grace 宽限期内。
	rec, err := f.svc.Revoke(ctx, RevokeInput{
		KeyName: "db", Version: 3, Reason: "leaked", Actor: "secops", RequestID: "rev-3",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rec.Version != 3 || rec.FallbackVersion != 2 {
		t.Fatalf("unexpected revocation record: %+v", rec)
	}

	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if info.Versions[2].Status != VersionRevoked {
		t.Fatalf("v3 status = %s, want revoked", info.Versions[2].Status)
	}
	if info.ActiveVersion != 3 || info.ServingVersion != 2 {
		t.Fatalf("active=%d serving=%d, want 3/2", info.ActiveVersion, info.ServingVersion)
	}
	if len(info.Revocations) != 1 || info.Revocations[0].ID != rec.ID {
		t.Fatalf("revocation record not exposed in status: %+v", info.Revocations)
	}

	// 读当前版本：立即得到接替版本 v2，并标记 Fallback。
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil {
		t.Fatalf("fallback read: %v", err)
	}
	if view.Version != 2 || string(view.Plaintext) != "v2-secret" || !view.Fallback {
		t.Fatalf("fallback view wrong: %+v", view)
	}

	// 被撤销版本永远不能再读，即使显式指定版本号。
	if _, err := f.svc.ReadSecret(ctx, "db", 3, "anyone"); err == nil {
		t.Fatalf("revoked version must not be readable")
	} else if ErrorCode(err) != CodeRevoked {
		t.Fatalf("want revoked code, got %v", err)
	}

	// 显式读取接替版本：可读但不标记 Fallback（该标记只属于“读当前版本”）。
	explicit, err := f.svc.ReadSecret(ctx, "db", 2, "anyone")
	if err != nil {
		t.Fatalf("explicit fallback read: %v", err)
	}
	if explicit.Version != 2 || explicit.Fallback || explicit.VersionStatus != VersionGrace {
		t.Fatalf("explicit grace read must not be flagged fallback: %+v", explicit)
	}
}

func TestRevokeActiveWithoutSafeHistoryHalts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// 无宽限期：v1 在 v2 激活的同一刻立即退役，不存在安全历史版本。
	f.createKey(t, "db", "v1-secret", 0)
	rotateToN(t, f, "db", 2, "v2-secret")

	rec, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, Reason: "leaked"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rec.FallbackVersion != 0 {
		t.Fatalf("want no fallback, got %d", rec.FallbackVersion)
	}

	info, _ := f.svc.Status(ctx, "db")
	if info.ServingVersion != 0 {
		t.Fatalf("serving = %d, want 0 (halted)", info.ServingVersion)
	}
	// 读取必须明确失败，绝不悄悄切到已退役的 v1。
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeRevoked)
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("error should explain revocation, got %v", err)
	}
	// 唯一版本被撤销（连历史都没有）同样明确失败。
	f.createKey(t, "solo", "only-secret", 0)
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "solo", Version: 1}); err != nil {
		t.Fatalf("revoke solo: %v", err)
	}
	_, err = f.svc.ReadSecret(ctx, "solo", 0, "anyone")
	mustCode(t, err, CodeRevoked)
}

func TestRevokedGraceVersionNeverChosenAsFallback(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")

	// 先撤销历史版本 v1（它仍在 grace）。
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 1, Reason: "older leak"}); err != nil {
		t.Fatalf("revoke v1: %v", err)
	}
	// 再撤销当前 v2：v1 已被撤销，绝不能被选为接替者，必须停止服务。
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, Reason: "leaked"}); err != nil {
		t.Fatalf("revoke v2: %v", err)
	}
	info, _ := f.svc.Status(ctx, "db")
	if info.ServingVersion != 0 {
		t.Fatalf("revoked v1 must not be selected as fallback, serving=%d", info.ServingVersion)
	}
	_, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeRevoked)
}

func TestRevokeGraceVersionDoesNotDisturbActive(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")

	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 1, Reason: "leaked"}); err != nil {
		t.Fatalf("revoke v1: %v", err)
	}
	// active 版本照常服务，服务指针不动。
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 2 || view.Fallback {
		t.Fatalf("active read disturbed by grace revocation: %+v %v", view, err)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 1, "anyone")
	mustCode(t, err, CodeRevoked)
}

// --- 接替版本失效后停止提供，不自行换版本 --------------------------------------

func TestFallbackExpiryHaltsServingAndNeverReselects(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// v1 只有 1 分钟宽限。
	f.createKey(t, "db", "v1-secret", time.Minute)
	rotateToN(t, f, "db", 2, "v2-secret")
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, Reason: "leaked"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// 接替版本 v1 宽限期内仍服务。
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 1 {
		t.Fatalf("fallback read: %+v %v", view, err)
	}

	f.clock.advance(time.Minute + time.Second)
	// 接替版本到期：原子退役 + 停止服务，返回过期错误。
	_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeExpired)
	info, _ := f.svc.Status(ctx, "db")
	if info.ServingVersion != 0 || info.Versions[0].Status != VersionRetired {
		t.Fatalf("fallback not halted/retired: serving=%d v1=%s", info.ServingVersion, info.Versions[0].Status)
	}
	// 此后读取明确失败，不会自行切到任何其他版本（被撤销的 v2 更不可能）。
	for i := 0; i < 3; i++ {
		_, err = f.svc.ReadSecret(ctx, "db", 0, "anyone")
		mustCode(t, err, CodeRevoked)
	}
}

func TestFallbackRevocationHaltsServing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, Reason: "leaked"}); err != nil {
		t.Fatalf("revoke v2: %v", err)
	}
	// 接替版本 v1 随后也被撤销：停止服务，不自行另选。
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 1, Reason: "also leaked"}); err != nil {
		t.Fatalf("revoke fallback v1: %v", err)
	}
	_, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	mustCode(t, err, CodeRevoked)
}

// --- 幂等 --------------------------------------------------------------------

func TestRevokeIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")

	in := RevokeInput{KeyName: "db", Version: 2, Reason: "leaked", Actor: "secops", RequestID: "rev-1"}
	first, err := f.svc.Revoke(ctx, in)
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// 同请求号重放：同一条记录。
	replay, err := f.svc.Revoke(ctx, in)
	if err != nil || replay.ID != first.ID {
		t.Fatalf("request-id replay not idempotent: %+v %v", replay, err)
	}
	// 不带请求号重复撤销同版本：同样幂等返回既有记录。
	again, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2})
	if err != nil || again.ID != first.ID {
		t.Fatalf("duplicate revoke not idempotent: %+v %v", again, err)
	}
	// 同请求号用于撤销不同版本 -> 冲突。
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 1, RequestID: "rev-1"})
	mustCode(t, err, CodeConflict)

	info, _ := f.svc.Status(ctx, "db")
	if len(info.Revocations) != 1 {
		t.Fatalf("idempotent retries created %d revocation records", len(info.Revocations))
	}
	if got := len(f.audit.EventsByAction("version_revoked")); got != 1 {
		t.Fatalf("version_revoked audited %d times, want exactly 1", got)
	}
}

func TestRevokeInvalidTargets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", 0)
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("v2"), Policy: Policy{}, RequestID: "start-2",
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// 参数校验。
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "", Version: 1})
	mustCode(t, err, CodeInvalidArgument)
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 0})
	mustCode(t, err, CodeInvalidArgument)
	// 不存在的密钥/版本。
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "missing", Version: 1})
	mustCode(t, err, CodeNotFound)
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 99})
	mustCode(t, err, CodeNotFound)
	// pending 版本不可撤销（应取消轮换）。
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: r.PendingVersion})
	mustCode(t, err, CodeFailedPrecondition)
	// 取消后 pending 版本退役，撤销退役版本同样被拒绝。
	if _, err := f.svc.Cancel(ctx, "db", r.ID, "cancel-1"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	_, err = f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: r.PendingVersion})
	mustCode(t, err, CodeFailedPrecondition)
}

// --- 撤销后正常轮换恢复服务，被撤销版本永不复活 ---------------------------------

func TestRotationAfterRevokeRestoresServiceAndKeepsRevokedTerminal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")
	if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, Reason: "leaked"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// 紧急轮换出全新安全版本 v3 并激活，服务恢复；v2 必须保持 revoked。
	rotateToN(t, f, "db", 3, "v3-secret")
	info, _ := f.svc.Status(ctx, "db")
	if info.ActiveVersion != 3 || info.ServingVersion != 3 {
		t.Fatalf("service not restored: active=%d serving=%d", info.ActiveVersion, info.ServingVersion)
	}
	if info.Versions[1].Status != VersionRevoked {
		t.Fatalf("revoked v2 came back to life: %s", info.Versions[1].Status)
	}
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 3 || string(view.Plaintext) != "v3-secret" || view.Fallback {
		t.Fatalf("read after recovery wrong: %+v %v", view, err)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 2, "anyone")
	mustCode(t, err, CodeRevoked)
}

// --- 读 / 撤销并发：撤销后不得再向新读取提供泄露版本 -----------------------------

func TestConcurrentReadAndRevoke(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// 长宽限：v1 始终是有效接替者，排除过期噪音，专注撤销线性化。
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")

	const readers = 32
	var wg sync.WaitGroup
	var servedMu sync.Mutex
	var served []int
	start := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
			if err == nil {
				servedMu.Lock()
				served = append(served, view.Version)
				servedMu.Unlock()
				if view.Version == 2 && view.Fallback {
					t.Errorf("revoked v2 served with fallback flag")
				}
			} else if ErrorCode(err) != CodeRevoked && ErrorCode(err) != CodeExpired {
				t.Errorf("unexpected read error during revocation: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, Reason: "leaked"}); err != nil {
			t.Errorf("revoke: %v", err)
		}
	}()
	close(start)
	wg.Wait()

	// happens-after 撤销完成：此后的每个新读取都只能拿到接替版本 v1，
	// 绝不能再拿到泄露的 v2。
	for i := 0; i < 16; i++ {
		view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
		if err != nil {
			t.Fatalf("post-revoke read should serve fallback: %v", err)
		}
		if view.Version != 1 || !view.Fallback || string(view.Plaintext) != "v1-secret" {
			t.Fatalf("post-revoke read must serve pinned fallback v1, got %+v", view)
		}
	}
	for _, v := range served {
		if v != 1 && v != 2 {
			t.Fatalf("read served an unexpected version: %d", v)
		}
	}
}

// --- 撤销 / 激活并发：终态不被覆盖，恢复路径安全 --------------------------------

func TestConcurrentRevokeAndActivate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createKey(t, "db", "v1-secret", time.Hour)
	rotateToN(t, f, "db", 2, "v2-secret")
	// v3 已 pending 且门槛已满足（空快照），撤销 v2 与激活 v3 直接竞争。
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("v3-secret"), Policy: Policy{}, RequestID: "start-v3",
	})
	if err != nil {
		t.Fatalf("start v3: %v", err)
	}

	const n = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				_, _ = f.svc.Revoke(ctx, RevokeInput{KeyName: "db", Version: 2, RequestID: fmt.Sprintf("rev-%d", i)})
			} else {
				_, _ = f.svc.Activate(ctx, "db", r.ID, fmt.Sprintf("act-%d", i))
			}
		}(i)
	}
	close(start)
	wg.Wait()

	info, err := f.svc.Status(ctx, "db")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	// v3 必然激活成功（空快照），服务恢复到 v3。
	if info.ActiveVersion != 3 || info.ServingVersion != 3 ||
		info.Versions[2].Status != VersionActive {
		t.Fatalf("v3 should be active and serving: %+v", info)
	}
	// v2 无论撤销先提交还是激活先提交，最终都必须保持 revoked
	// （激活先提交时 v2 先进 grace，撤销随后终结它）。
	if info.Versions[1].Status != VersionRevoked {
		t.Fatalf("v2 must end revoked, got %s", info.Versions[1].Status)
	}
	if len(info.Revocations) != 1 {
		t.Fatalf("want exactly one revocation record, got %d", len(info.Revocations))
	}
	view, err := f.svc.ReadSecret(ctx, "db", 0, "anyone")
	if err != nil || view.Version != 3 || string(view.Plaintext) != "v3-secret" {
		t.Fatalf("post-race serving wrong: %+v %v", view, err)
	}
	_, err = f.svc.ReadSecret(ctx, "db", 2, "anyone")
	mustCode(t, err, CodeRevoked)
}

// --- 原子保存与机密性：撤销不泄漏明文 -------------------------------------------

func TestRevocationAtomicRecordAndNoPlaintextLeak(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := "REVOKE-PROBE-密钥"
	f.createKey(t, "db", secret, time.Hour)
	rotateToN(t, f, "db", 2, secret+"-v2")
	if _, err := f.svc.Revoke(ctx, RevokeInput{
		KeyName: "db", Version: 2, Reason: "leak-simulated", Actor: "secops", RequestID: "rev-2",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := f.svc.ReadSecret(ctx, "db", 2, "anyone"); err == nil {
		t.Fatalf("expected revoked read error")
	}
	if _, err := f.svc.ReadSecret(ctx, "db", 0, "anyone"); err != nil {
		t.Fatalf("fallback read: %v", err)
	}

	st, err := f.store.Get(ctx, "db")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// 状态与撤销记录在同一份 KeyState 中（单次 CAS）原子保存。
	if len(st.Revocations) != 1 || st.Revocations[0].Version != 2 ||
		st.RevocationRequests["rev-2"] == "" {
		t.Fatalf("revocation record not atomically persisted: %+v", st.Revocations)
	}
	if st.Versions[1].Status != VersionRevoked || st.ServingVersion != 1 {
		t.Fatalf("revocation state not persisted: status=%s serving=%d",
			st.Versions[1].Status, st.ServingVersion)
	}

	dump := fmt.Sprintf("%+v", st)
	for _, probe := range []string{secret, secret + "-v2"} {
		if strings.Contains(dump, probe) {
			t.Fatalf("plaintext leaked into persisted state: %q", probe)
		}
	}
	for _, ev := range f.audit.Events() {
		blob := fmt.Sprintf("%+v", ev)
		for _, probe := range []string{secret, secret + "-v2"} {
			if strings.Contains(blob, probe) {
				t.Fatalf("plaintext leaked into audit event: %+v", ev)
			}
		}
	}

	// 撤销相关错误文本不得携带明文。
	_, e1 := f.svc.ReadSecret(ctx, "db", 2, "anyone")
	if e1 == nil || strings.Contains(e1.Error(), secret) {
		t.Fatalf("revoked read error missing or leaking: %v", e1)
	}
}
