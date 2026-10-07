package secretrotation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// rotateKeyToV2 建立密钥 v1 并完成一次轮换激活到 v2，模拟“紧急撤销后
// 已发布安全版本 v2”的场景。
func rotateKeyToV2(t *testing.T, f *fixture, name, secret string, grace time.Duration, readers []string) {
	t.Helper()
	ctx := context.Background()
	f.createKey(t, name, secret+"-v1", grace, readers...)
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName:      name,
		NewPlaintext: []byte(secret + "-v2"),
		Policy:       Policy{},
		RequestID:    "start-" + name,
	})
	if err != nil {
		t.Fatalf("start rotation: %v", err)
	}
	if _, err := f.svc.Activate(ctx, name, r.ID, "activate-"+name); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func startTestAudit(t *testing.T, f *fixture, key, auditID string, services []string) *AuditInfo {
	t.Helper()
	info, err := f.svc.StartAudit(context.Background(), StartAuditInput{
		KeyName:   key,
		AuditID:   auditID,
		Services:  services,
		Deadline:  f.clock.now().Add(time.Hour),
		RequestID: "audit-start-" + auditID,
	})
	if err != nil {
		t.Fatalf("start audit: %v", err)
	}
	return info
}

func report(t *testing.T, f *fixture, in ReportInstanceInput) *AuditInfo {
	t.Helper()
	info, err := f.svc.ReportInstance(context.Background(), in)
	if err != nil {
		t.Fatalf("report %s/%s: %v", in.Service, in.Instance, err)
	}
	return info
}

func findServiceView(t *testing.T, info *AuditInfo, svc string) *ServiceAuditView {
	t.Helper()
	for i := range info.ServicesView {
		if info.ServicesView[i].Name == svc {
			return &info.ServicesView[i]
		}
	}
	t.Fatalf("service view not found: %s", svc)
	return nil
}

func findInstance(list []InstanceAuditView, instance string) *InstanceAuditView {
	for i := range list {
		if list[i].Instance == instance {
			return &list[i]
		}
	}
	return nil
}

// 需求 1：审计固定秘密标识、服务清单、安全版本与截止时间；
// 审计开始后新出现的实例必须自己回报安全版本才算达标。
func TestAuditPinsSnapshotAndNewInstancesNotPreComplete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	info := startTestAudit(t, f, "db", "aud-1", []string{"billing", "checkout"})

	if info.SafeVersion != 2 {
		t.Fatalf("safe version = %d, want 2", info.SafeVersion)
	}
	if info.Status != AuditOpen || len(info.Services) != 2 {
		t.Fatalf("unexpected audit: %+v", info)
	}
	if got := findServiceView(t, info, "billing").RevokedVersions; len(got) != 1 || got[0] != 1 {
		t.Fatalf("revoked versions = %v, want [1]", got)
	}

	// 审计开始后才出现的新实例：第一次回报旧版本 -> 未达标。
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-1", Service: "billing", Instance: "b-101", Version: 1})
	info, err := f.svc.GetAudit(ctx, "db", "aud-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	sv := findServiceView(t, info, "billing")
	if len(sv.Incomplete) != 1 || sv.Incomplete[0].Instance != "b-101" || sv.Incomplete[0].Complete {
		t.Fatalf("new instance on revoked version must be incomplete: %+v", sv.Incomplete)
	}
}

// 需求 2：回报、撤销与结案交错时，只有当前安全版本的回报计入；
// 未到截止时间不能提前结案。
func TestAuditInterleavedReportsAndNoEarlyClose(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-2", []string{"billing"})

	// 截止前尝试结案：必须拒绝。
	_, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-2"})
	mustCode(t, err, CodeFailedPrecondition)

	// 旧版本回报不计入；随后同一实例改为安全版本回报才计入。
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-2", Service: "billing", Instance: "b-1", Version: 1})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-2", Service: "billing", Instance: "b-1", Version: 2})
	f.clock.advance(2 * time.Hour)
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-2", RequestID: "close-2"})
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if closed.Status != AuditClosed {
		t.Fatalf("status = %s", closed.Status)
	}
	sv := findServiceView(t, closed, "billing")
	if len(sv.Complete) != 1 || sv.Complete[0].Instance != "b-1" {
		t.Fatalf("want b-1 complete, got %+v", sv.Complete)
	}
}

// 需求 2 补充：结案时 active 已不是审计固定的安全版本（期间又发生轮换），
// 旧版本/非当前安全版本的回报不能结案。
func TestAuditCloseFailsWhenSafeVersionMovedOn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-move", []string{"billing"})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-move", Service: "billing", Instance: "b-1", Version: 2})

	// 审计窗口内紧急撤销再次发生，v3 成为当前安全版本。
	r3, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName: "db", NewPlaintext: []byte("tok-v3"), Policy: Policy{}, RequestID: "start-v3",
	})
	if err != nil {
		t.Fatalf("start v3: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "db", r3.ID, "activate-v3"); err != nil {
		t.Fatalf("activate v3: %v", err)
	}
	f.clock.advance(2 * time.Hour)
	_, err = f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-move"})
	mustCode(t, err, CodeFailedPrecondition)
}

// 需求 3：重部署产生新实例时，必须按新实例实际版本重新判断，
// 不沿用旧实例的“已完成”标记（实例键不同，结论各自现算）。
func TestAuditRedeployRejudgesByNewInstanceVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-3", []string{"checkout"})

	// 旧实例已换到安全版本。
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-3", Service: "checkout", Instance: "c-old", Version: 2})
	// 重部署：新实例实际仍在跑被撤销的 v1，声明取代旧实例。
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-3", Service: "checkout", Instance: "c-new", Version: 1, Replaces: "c-old"})

	info, err := f.svc.GetAudit(ctx, "db", "aud-3")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	sv := findServiceView(t, info, "checkout")
	if old := findInstance(sv.Complete, "c-old"); old == nil {
		t.Fatalf("c-old should be complete on its own report: %+v", sv.Complete)
	}
	nw := findInstance(sv.Incomplete, "c-new")
	if nw == nil || nw.Complete || nw.Replaces != "c-old" {
		t.Fatalf("redeployed c-new must be judged by actual version, not inherit: %+v", sv.Incomplete)
	}

	// 新实例随后换到 v2，应转为达标；旧实例不受影响。
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-3", Service: "checkout", Instance: "c-new", Version: 2, Replaces: "c-old"})
	info, _ = f.svc.GetAudit(ctx, "db", "aud-3")
	sv = findServiceView(t, info, "checkout")
	if findInstance(sv.Complete, "c-new") == nil {
		t.Fatalf("c-new should become complete after reporting safe version: %+v", sv.Complete)
	}
}

// 截止后才到的回报不计入达标。
func TestAuditReportAfterDeadlineIncomplete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-late", []string{"billing"})
	f.clock.advance(2 * time.Hour)
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-late", Service: "billing", Instance: "b-late", Version: 2})
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-late"})
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	sv := findServiceView(t, closed, "billing")
	if len(sv.Complete) != 0 || len(sv.Incomplete) != 1 {
		t.Fatalf("post-deadline report must not count: complete=%v incomplete=%v", sv.Complete, sv.Incomplete)
	}
	if sv.Incomplete[0].BeforeDeadline {
		t.Fatalf("BeforeDeadline should be false")
	}
}

// 需求 4：相同审计号重复请求返回原结果；服务集合/截止时刻变化返回冲突。
func TestAuditIdempotentReplayAndConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	first := startTestAudit(t, f, "db", "aud-idem", []string{"billing"})

	// 相同参数重放（即使不带请求号）返回同一审计。
	replay, err := f.svc.StartAudit(ctx, StartAuditInput{
		KeyName: "db", AuditID: "aud-idem",
		Services: []string{"billing"}, Deadline: first.Deadline,
		RequestID: "audit-start-aud-idem",
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.CreatedAt != first.CreatedAt || replay.SafeVersion != first.SafeVersion {
		t.Fatalf("replay must return original audit")
	}

	// 服务集合变化 -> conflict。
	_, err = f.svc.StartAudit(ctx, StartAuditInput{
		KeyName: "db", AuditID: "aud-idem",
		Services: []string{"billing", "checkout"}, Deadline: first.Deadline,
	})
	mustCode(t, err, CodeConflict)

	// 截止时刻变化 -> conflict。
	_, err = f.svc.StartAudit(ctx, StartAuditInput{
		KeyName: "db", AuditID: "aud-idem",
		Services: []string{"billing"}, Deadline: first.Deadline.Add(time.Minute),
	})
	mustCode(t, err, CodeConflict)

	// 相同请求号复用到不同审计内容 -> conflict。
	_, err = f.svc.StartAudit(ctx, StartAuditInput{
		KeyName: "db", AuditID: "aud-other",
		Services: []string{"billing"}, Deadline: first.Deadline,
		RequestID: "audit-start-aud-idem",
	})
	mustCode(t, err, CodeConflict)
}

// 需求 4：相同审计号用于另一个秘密（密钥）返回冲突。
func TestAuditIDAcrossSecretsConflicts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db-a", "tokA", time.Minute, nil)
	rotateKeyToV2(t, f, "db-b", "tokB", time.Minute, nil)
	startTestAudit(t, f, "db-a", "shared-id", []string{"billing"})
	_, err := f.svc.StartAudit(ctx, StartAuditInput{
		KeyName: "db-b", AuditID: "shared-id",
		Services: []string{"billing"}, Deadline: f.clock.now().Add(time.Hour),
	})
	mustCode(t, err, CodeConflict)
}

// 回报的请求号幂等与内容冲突；非清单成员、非法版本被拒绝。
func TestAuditReportIdempotencyAndValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-rep", []string{"billing"})

	in := ReportInstanceInput{KeyName: "db", AuditID: "aud-rep", Service: "billing", Instance: "b-1", Version: 1, RequestID: "r1"}
	first := report(t, f, in)
	// 同请求号同内容重放安全返回。
	replay := report(t, f, in)
	if len(replay.Instances) != len(first.Instances) {
		t.Fatalf("replay must not duplicate report")
	}
	// 同请求号不同内容 -> conflict。
	in.Instance = "b-2"
	_, err := f.svc.ReportInstance(ctx, in)
	mustCode(t, err, CodeConflict)

	// 非冻结清单成员 -> permission_denied。
	_, err = f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "db", AuditID: "aud-rep", Service: "intruder", Instance: "x", Version: 2,
	})
	mustCode(t, err, CodePermissionDenied)
	// 不存在的版本 -> invalid_argument。
	_, err = f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "db", AuditID: "aud-rep", Service: "billing", Instance: "b-3", Version: 99,
	})
	mustCode(t, err, CodeInvalidArgument)
}

// 需求 6：结案只代表当时结果；之后发现旧版本实例追加问题记录，
// 不改写结案，且同一问题去重。
func TestAuditPostCloseIssuesAppendOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-post", []string{"billing"})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-post", Service: "billing", Instance: "b-1", Version: 2})
	f.clock.advance(2 * time.Hour)
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-post", RequestID: "close-post"})
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(closed.Issues) != 0 {
		t.Fatalf("fresh close should have no issues: %+v", closed.Issues)
	}
	closedAt := closed.ClosedAt

	// 结案后发现仍在跑被撤销 v1 的实例 -> 新问题记录。
	after, err := f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "db", AuditID: "aud-post", Service: "billing", Instance: "b-stray", Version: 1, RequestID: "issue-r1",
	})
	if err != nil {
		t.Fatalf("post-close report: %v", err)
	}
	if len(after.Issues) != 1 || after.Issues[0].Instance != "b-stray" || after.Issues[0].Version != 1 {
		t.Fatalf("expected one issue, got %+v", after.Issues)
	}
	if after.Status != AuditClosed || !after.ClosedAt.Equal(closedAt) {
		t.Fatalf("close result must not be rewritten")
	}
	// 结案时的达标快照保持不变。
	sv := findServiceView(t, after, "billing")
	if len(sv.Complete) != 1 || sv.Complete[0].Instance != "b-1" {
		t.Fatalf("closed snapshot must be immutable: %+v", sv.Complete)
	}

	// 重复回报同一旧实例/版本不重复建问题。
	again, err := f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "db", AuditID: "aud-post", Service: "billing", Instance: "b-stray", Version: 1, RequestID: "issue-r1",
	})
	if err != nil {
		t.Fatalf("dedupe replay: %v", err)
	}
	if len(again.Issues) != 1 {
		t.Fatalf("issue must be deduplicated, got %d", len(again.Issues))
	}

	// 结案后回报当前安全版本不产生问题。
	safe, err := f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "db", AuditID: "aud-post", Service: "billing", Instance: "b-2", Version: 2,
	})
	if err != nil {
		t.Fatalf("post-close safe report: %v", err)
	}
	if len(safe.Issues) != 1 {
		t.Fatalf("safe version report must not open an issue, got %d", len(safe.Issues))
	}
}

// 结案天然幂等，重复结案返回同一结果。
func TestAuditCloseIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-c", []string{"billing"})
	f.clock.advance(2 * time.Hour)
	first, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-c", RequestID: "rc"})
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	second, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-c", RequestID: "rc"})
	if err != nil {
		t.Fatalf("replay close: %v", err)
	}
	if !second.ClosedAt.Equal(first.ClosedAt) {
		t.Fatalf("close must be idempotent")
	}
	// 不同请求号结案已结案审计 -> conflict。
	_, err = f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-c", RequestID: "other"})
	mustCode(t, err, CodeConflict)
}

// 需求 7：重部署竞态——大量实例并发回报与并发结案交错，结果必须自洽：
// 只有截止前回报安全版本的实例达标，计数与实例视图一致，无数据竞争。
func TestAuditRedeployConcurrentReportsRace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-race", []string{"billing"})

	const n = 40
	var wg sync.WaitGroup
	// 一半实例并发回报安全 v2（截止前），另一半回报被撤销 v1。
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			version := 1
			if i%2 == 0 {
				version = 2
			}
			_, _ = f.svc.ReportInstance(ctx, ReportInstanceInput{
				KeyName: "db", AuditID: "aud-race", Service: "billing",
				Instance: fmt.Sprintf("b-%02d", i), Version: version,
			})
		}()
	}
	wg.Wait()

	f.clock.advance(2 * time.Hour)
	// 并发结案：多次调用必须要么失败（已被他人结案的幂等重放仍应成功），
	// 最终只产生一个一致结果。
	const closers = 8
	var cwg sync.WaitGroup
	results := make(chan *AuditInfo, closers)
	for i := 0; i < closers; i++ {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			info, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-race"})
			if err == nil {
				results <- info
			}
		}()
	}
	cwg.Wait()
	close(results)

	var final *AuditInfo
	for info := range results {
		if final == nil {
			final = info
		} else if !info.ClosedAt.Equal(final.ClosedAt) {
			t.Fatalf("concurrent closes diverged")
		}
	}
	if final == nil {
		t.Fatalf("no close succeeded")
	}
	sv := findServiceView(t, final, "billing")
	if len(sv.Complete) != n/2 || len(sv.Incomplete) != n/2 {
		t.Fatalf("race tally wrong: complete=%d incomplete=%d", len(sv.Complete), len(sv.Incomplete))
	}
	// 每个实例只出现一次。
	seen := map[string]int{}
	for _, iv := range append(append([]InstanceAuditView{}, sv.Complete...), sv.Incomplete...) {
		seen[iv.Instance]++
	}
	if len(seen) != n {
		t.Fatalf("want %d distinct instances, got %d", n, len(seen))
	}
}

// 需求 5：查询展示当前版本、撤销版本、最近回报与未达标实例。
func TestAuditQueryShowsVersionsLastReportAndIncomplete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rotateKeyToV2(t, f, "db", "tok", time.Minute, nil)
	startTestAudit(t, f, "db", "aud-q", []string{"billing", "checkout"})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-q", Service: "billing", Instance: "b-1", Version: 1})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-q", Service: "billing", Instance: "b-1", Version: 2})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-q", Service: "checkout", Instance: "c-1", Version: 1})

	info, err := f.svc.GetAudit(ctx, "db", "aud-q")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(info.RevokedVersions) != 1 || info.RevokedVersions[0] != 1 {
		t.Fatalf("revoked = %v", info.RevokedVersions)
	}
	billing := findServiceView(t, info, "billing")
	if billing.LastReport == nil || billing.LastReport.Version != 2 || billing.LastReport.Instance != "b-1" {
		t.Fatalf("last report wrong: %+v", billing.LastReport)
	}
	if len(billing.Complete) != 1 || len(billing.Incomplete) != 0 {
		t.Fatalf("billing tally wrong: %+v / %+v", billing.Complete, billing.Incomplete)
	}
	checkout := findServiceView(t, info, "checkout")
	if len(checkout.Incomplete) != 1 || checkout.Incomplete[0].Instance != "c-1" {
		t.Fatalf("checkout incomplete wrong: %+v", checkout.Incomplete)
	}
	if checkout.LastReport == nil || checkout.LastReport.Version != 1 {
		t.Fatalf("checkout last report wrong: %+v", checkout.LastReport)
	}

	// 不存在的审计/密钥。
	_, err = f.svc.GetAudit(ctx, "db", "missing")
	mustCode(t, err, CodeNotFound)
	_, err = f.svc.GetAudit(ctx, "nope", "aud-q")
	mustCode(t, err, CodeNotFound)
}

// 需求 7/4：审计持久化记录、审计事件与错误文本都不得包含秘密明文。
func TestAuditNeverPersistsPlaintext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := "AUDIT-SECRET-PROBE-密钥"
	rotateKeyToV2(t, f, "db", secret, time.Minute, nil)
	startTestAudit(t, f, "db", "aud-sec", []string{"billing"})
	report(t, f, ReportInstanceInput{KeyName: "db", AuditID: "aud-sec", Service: "billing", Instance: "b-1", Version: 1})
	f.clock.advance(2 * time.Hour)
	if _, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "db", AuditID: "aud-sec"}); err != nil {
		t.Fatalf("close: %v", err)
	}
	// 结案后旧版本实例 -> 问题记录。
	if _, err := f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "db", AuditID: "aud-sec", Service: "billing", Instance: "b-stray", Version: 1,
	}); err != nil {
		t.Fatalf("post-close report: %v", err)
	}

	st, err := f.store.Get(ctx, "db")
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	dump := fmt.Sprintf("%+v", st)
	for _, probe := range []string{secret, secret + "-v1", secret + "-v2"} {
		if strings.Contains(dump, probe) {
			t.Fatalf("plaintext leaked into audit persistence: %q", probe)
		}
	}
	for _, ev := range f.audit.Events() {
		blob := fmt.Sprintf("%+v", ev)
		for _, probe := range []string{secret, secret + "-v1", secret + "-v2"} {
			if strings.Contains(blob, probe) {
				t.Fatalf("plaintext leaked into audit event: %+v", ev)
			}
		}
	}

	// 错误文本同样不得泄漏明文。
	for _, e := range []error{
		func() error {
			_, err := f.svc.StartAudit(ctx, StartAuditInput{KeyName: "db", AuditID: ""})
			return err
		}(),
		func() error {
			_, err := f.svc.GetAudit(ctx, "db", "nope")
			return err
		}(),
	} {
		if e != nil && strings.Contains(e.Error(), secret) {
			t.Fatalf("plaintext leaked in error: %v", e)
		}
	}
}
