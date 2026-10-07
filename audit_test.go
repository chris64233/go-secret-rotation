package secretrotation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const auditProbeSecret = "AUDIT-SECRET-PROBE-明文"

// setupAuditedKey 建立一个已轮换到 v2 安全版本、v1 已被撤销（grace）的密钥。
func setupAuditedKey(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	f.createKey(t, "payments", auditProbeSecret, time.Hour)
	r, err := f.svc.StartRotation(ctx, StartRotationInput{
		KeyName:      "payments",
		NewPlaintext: []byte(auditProbeSecret + "-v2"),
		Policy:       Policy{RequiredConsumers: nil},
		RequestID:    "rot-1",
	})
	if err != nil {
		t.Fatalf("start rotation: %v", err)
	}
	if _, err := f.svc.Activate(ctx, "payments", r.ID, "rot-act"); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func doReport(t *testing.T, f *fixture, in ReportInstanceInput) {
	t.Helper()
	if err := f.svc.ReportInstance(context.Background(), in); err != nil {
		t.Fatalf("report %s/%s g%d v%d: %v", in.Service, in.InstanceID, in.DeployGeneration, in.Version, err)
	}
}

func auditDeadline(f *fixture) time.Time {
	return f.clock.now().Add(time.Hour)
}

func getAudit(t *testing.T, f *fixture) *AuditInfo {
	t.Helper()
	a, err := f.svc.GetAudit(context.Background(), "payments", "audit-1")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	return a
}

func serviceResult(a *AuditInfo, service string) *ServiceAuditInfo {
	for i := range a.ServiceResults {
		if a.ServiceResults[i].Name == service {
			return &a.ServiceResults[i]
		}
	}
	return nil
}

func serviceAllComplete(a *AuditInfo, service string) bool {
	res := serviceResult(a, service)
	return res != nil && len(res.Incomplete) == 0
}

// 需求 1：审计固定秘密标识、服务清单和截止时间；审计开始后新出现的实例
// 不能被算作已经完成。
func TestAuditFreezesScopeAndSnapshot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	// 审计开始前：billing 两个实例已换到安全版本 v2；checkout 仍在 v1。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 2})
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-2", DeployGeneration: 1, Version: 2})
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "checkout", InstanceID: "c-1", DeployGeneration: 1, Version: 1})

	a, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing", "checkout"}, Deadline: auditDeadline(f),
		RequestID: "audit-create-1",
	})
	if err != nil {
		t.Fatalf("create audit: %v", err)
	}
	if a.SafeVersion != 2 {
		t.Fatalf("safe version = %d, want 2", a.SafeVersion)
	}
	if len(a.RevokedVersions) != 1 || a.RevokedVersions[0] != 1 {
		t.Fatalf("revoked versions = %v, want [1]", a.RevokedVersions)
	}

	// 审计开始之后才出现的实例：即便立刻回报安全版本，也不能算作完成。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-late-new", DeployGeneration: 1, Version: 2})
	a = getAudit(t, f)
	res := serviceResult(a, "billing")
	var lateInstance *InstanceAuditInfo
	for i := range res.Incomplete {
		if res.Incomplete[i].InstanceID == "b-late-new" {
			lateInstance = &res.Incomplete[i]
		}
	}
	if lateInstance == nil {
		t.Fatalf("post-start instance must remain incomplete: %+v", res)
	}
	if lateInstance.InSnapshot {
		t.Fatalf("post-start instance must be flagged outside snapshot")
	}

	// checkout 仍在被撤销版本上：截止前结案必须被拒绝，旧版本不能提前结案。
	_, err = f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"})
	mustCode(t, err, CodeFailedPrecondition)
	// 超过截止时间后允许以“未全部完成”结案。
	f.clock.advance(2 * time.Hour)
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"})
	if err != nil {
		t.Fatalf("close after deadline: %v", err)
	}
	if closed.FullyComplete {
		t.Fatalf("audit must not be fully complete while checkout is on revoked version")
	}
}

// 需求 2：服务回报、撤销与审计结案交错时，只有当前安全版本的回报计入，
// 旧版本不能提前结案。
func TestAuditOnlySafeVersionReportsCount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 1})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	// 快照实例仍在旧（被撤销）版本：截止前结案被拒绝，不能提前结案。
	_, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"})
	mustCode(t, err, CodeFailedPrecondition)

	// 截止前换到安全版本后重新结案：结论代表结案当时状态。
	f.clock.advance(time.Minute)
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 2})
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1", RequestID: "close-1"})
	if err != nil {
		t.Fatalf("re-close: %v", err)
	}
	if !closed.FullyComplete || closed.Status != AuditClosed {
		t.Fatalf("want fully complete closed audit, got %+v", closed)
	}
}

// 需求 3：服务在截止前重新部署时，按新部署的实际版本重新判断，
// 不沿用旧实例的“已完成”标记。
func TestRedeployBeforeDeadlineRejudgedByActualVersion(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 2})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	if a := getAudit(t, f); !serviceAllComplete(a, "billing") {
		t.Fatalf("snapshot instance should start complete")
	}

	// 截止前重新部署但回滚到被撤销版本 v1：不得沿用“已完成”。
	f.clock.advance(time.Minute)
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 1})
	res := serviceResult(getAudit(t, f), "billing")
	if len(res.Incomplete) != 1 || res.Incomplete[0].LastVersion != 1 {
		t.Fatalf("redeployed instance must be re-judged incomplete: %+v", res.Incomplete)
	}

	// 再次部署换回安全版本：重新达标并可结案。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 3, Version: 2})
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"})
	if err != nil || !closed.FullyComplete {
		t.Fatalf("want complete after re-redeploy: %+v %v", closed, err)
	}
}

// 重部署竞态：旧部署的迟到回报不能覆盖新部署的版本结论。
func TestRedeployRaceStaleGenerationIgnored(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 2})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 2})
	// 旧部署（generation=1）的迟到回报声称仍在 v1：必须被忽略。
	if err := f.svc.ReportInstance(ctx, ReportInstanceInput{
		KeyName: "payments", Service: "billing", InstanceID: "b-1",
		DeployGeneration: 1, Version: 1,
	}); err != nil {
		t.Fatalf("stale report should be ignored without error, got: %v", err)
	}
	res := serviceResult(getAudit(t, f), "billing")
	if len(res.Incomplete) != 0 {
		t.Fatalf("stale generation report must not downgrade instance: %+v", res.Incomplete)
	}
	st, _ := f.store.Get(ctx, "payments")
	if got := st.Instances["billing"]["b-1"]; got.DeployGeneration != 2 || got.Version != 2 {
		t.Fatalf("registry downgraded by stale report: %+v", got)
	}
}

// 截止时间之后的回报不能再计入完成。
func TestLateReportsAfterDeadlineDoNotCount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 1})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	f.clock.advance(2 * time.Hour)
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 2})
	res := serviceResult(getAudit(t, f), "billing")
	if len(res.Incomplete) != 1 || !res.Incomplete[0].Late {
		t.Fatalf("after-deadline report must be flagged late/incomplete: %+v", res.Incomplete)
	}
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"})
	if err != nil || closed.FullyComplete {
		t.Fatalf("late completion must not close as complete: %+v %v", closed, err)
	}
}

// 需求 4：相同审计号重复请求返回原结果；秘密或服务集合变化返回冲突。
func TestCreateAuditIdempotencyAndConflicts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	in := CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
		RequestID: "req-audit-1",
	}
	first, err := f.svc.CreateAudit(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// 完全相同的重复请求：返回原结果。
	replay, err := f.svc.CreateAudit(ctx, in)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.AuditID != first.AuditID || !replay.StartedAt.Equal(first.StartedAt) {
		t.Fatalf("replay must return the original audit")
	}
	// 换 RequestID 的相同审计号请求：仍是同一审计。
	in.RequestID = "req-audit-retry"
	replay2, err := f.svc.CreateAudit(ctx, in)
	if err != nil || !replay2.StartedAt.Equal(first.StartedAt) {
		t.Fatalf("retry with new request id must return original: %+v %v", replay2, err)
	}

	// 服务集合变化 -> 冲突。
	in.Services = []string{"billing", "checkout"}
	in.RequestID = "req-audit-2"
	_, err = f.svc.CreateAudit(ctx, in)
	mustCode(t, err, CodeConflict)

	// 截止时间变化 -> 冲突。
	in.Services = []string{"billing"}
	in.Deadline = first.Deadline.Add(time.Hour)
	in.RequestID = "req-audit-3"
	_, err = f.svc.CreateAudit(ctx, in)
	mustCode(t, err, CodeConflict)

	// 同一 RequestID 用于不同审计 -> 冲突。
	other := CreateAuditInput{
		KeyName: "payments", AuditID: "audit-2",
		Services: []string{"checkout"}, Deadline: auditDeadline(f),
		RequestID: "req-audit-1",
	}
	_, err = f.svc.CreateAudit(ctx, other)
	mustCode(t, err, CodeConflict)

	// 同审计号用于另一个秘密 -> 冲突。
	f.createKey(t, "orders", "other-secret", time.Hour)
	_, err = f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "orders", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	})
	mustCode(t, err, CodeConflict)
}

// 需求 4：回报幂等——相同请求号重放安全；不同内容冲突。
func TestReportInstanceIdempotencyAndConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	in := ReportInstanceInput{
		KeyName: "payments", Service: "billing", InstanceID: "b-1",
		DeployGeneration: 1, Version: 2, RequestID: "rep-1",
	}
	if err := f.svc.ReportInstance(ctx, in); err != nil {
		t.Fatalf("first report: %v", err)
	}
	if err := f.svc.ReportInstance(ctx, in); err != nil {
		t.Fatalf("identical replay should be idempotent: %v", err)
	}
	// 同请求号、不同版本 -> 冲突。
	bad := in
	bad.Version = 1
	mustCode(t, f.svc.ReportInstance(ctx, bad), CodeConflict)
	// 同请求号、不同实例 -> 冲突。
	bad = in
	bad.InstanceID = "b-2"
	mustCode(t, f.svc.ReportInstance(ctx, bad), CodeConflict)
}

// 需求 5：查询展示安全版本、撤销版本和未完成实例；按服务查看最近回报。
func TestAuditQueriesAndServiceView(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 2})
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-2", DeployGeneration: 1, Version: 1})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing", "checkout"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	a, err := f.svc.GetAudit(ctx, "payments", "audit-1")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	if a.SafeVersion != 2 || len(a.RevokedVersions) != 1 || a.RevokedVersions[0] != 1 {
		t.Fatalf("unexpected versions: safe=%d revoked=%v", a.SafeVersion, a.RevokedVersions)
	}
	billing := serviceResult(a, "billing")
	if len(billing.Complete) != 1 || billing.Complete[0].InstanceID != "b-1" {
		t.Fatalf("billing complete set wrong: %+v", billing.Complete)
	}
	if len(billing.Incomplete) != 1 || billing.Incomplete[0].InstanceID != "b-2" {
		t.Fatalf("billing incomplete set wrong: %+v", billing.Incomplete)
	}
	// checkout 没有任何回报：仍作为服务列出且无完成实例。
	checkout := serviceResult(a, "checkout")
	if checkout == nil || len(checkout.Complete) != 0 || len(checkout.Incomplete) != 0 {
		t.Fatalf("checkout service missing: %+v", checkout)
	}

	// 按服务查看最近回报（新的在前）与未达标实例。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-2", DeployGeneration: 2, Version: 2})
	view, err := f.svc.GetServiceAuditView(ctx, "payments", "audit-1", "billing")
	if err != nil {
		t.Fatalf("service view: %v", err)
	}
	if view.SafeVersion != 2 || view.RevokedVersions[0] != 1 {
		t.Fatalf("service view versions wrong: %+v", view)
	}
	if len(view.RecentReports) < 2 || view.RecentReports[0].InstanceID != "b-2" {
		t.Fatalf("recent reports order wrong: %+v", view.RecentReports)
	}
	if len(view.Outstanding) != 0 {
		t.Fatalf("b-2 redeployed to safe version, outstanding should be empty: %+v", view.Outstanding)
	}

	// 审计开始后新出现的实例也进入未达标列表。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-3", DeployGeneration: 1, Version: 1})
	view, err = f.svc.GetServiceAuditView(ctx, "payments", "audit-1", "billing")
	if err != nil {
		t.Fatalf("service view: %v", err)
	}
	if len(view.Outstanding) != 1 || view.Outstanding[0].InstanceID != "b-3" || view.Outstanding[0].InSnapshot {
		t.Fatalf("new post-start instance must be outstanding: %+v", view.Outstanding)
	}

	// 非清单内服务查询 -> not_found。
	_, err = f.svc.GetServiceAuditView(ctx, "payments", "audit-1", "unknown")
	mustCode(t, err, CodeNotFound)
	_, err = f.svc.GetAudit(ctx, "payments", "missing")
	mustCode(t, err, CodeNotFound)
}

// 需求 6：结案只代表当时结果；之后发现旧版本实例时创建新的问题记录，
// 不能改写历史结案。
func TestPostCloseFindingsCreateIssuesWithoutRewritingHistory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 2})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	closed, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1", RequestID: "close-1"})
	if err != nil || !closed.FullyComplete {
		t.Fatalf("want fully complete close: %+v %v", closed, err)
	}

	// 结案后：b-1 重新部署（g2）但仍在用被撤销版本 v1 -> 追加问题记录。
	f.clock.advance(time.Minute)
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 1})
	a := getAudit(t, f)
	if !a.FullyComplete || a.ClosedAt != closed.ClosedAt {
		t.Fatalf("historical close must remain unchanged: %+v", a)
	}
	if len(a.Issues) != 1 {
		t.Fatalf("want one post-close issue, got %d: %+v", len(a.Issues), a.Issues)
	}
	issue := a.Issues[0]
	if issue.InstanceID != "b-1" || issue.Version != 1 || issue.DeployGeneration != 2 {
		t.Fatalf("issue content wrong: %+v", issue)
	}

	// 相同发现重复回报：不重复创建问题。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 1})
	if a = getAudit(t, f); len(a.Issues) != 1 {
		t.Fatalf("duplicate finding must not create another issue: %+v", a.Issues)
	}

	// 再次部署到安全版本：不产生新问题；历史结论仍不变。
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 3, Version: 2})
	if a = getAudit(t, f); len(a.Issues) != 1 || !a.FullyComplete {
		t.Fatalf("safe version after issue must not change history/issues: %+v", a)
	}

	// 结案操作本身幂等：重复结案返回同一冻结结果，不产生新事件。
	n := len(f.audit.EventsByAction("audit_closed"))
	again, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"})
	if err != nil || !again.FullyComplete || !again.ClosedAt.Equal(closed.ClosedAt) {
		t.Fatalf("idempotent close mismatch: %+v %v", again, err)
	}
	if got := len(f.audit.EventsByAction("audit_closed")); got != n {
		t.Fatalf("re-close emitted another audit_closed event: %d", got)
	}
}

// 需求 7：敏感信息保护——审计记录、回报、问题记录与错误文本都不得包含明文。
func TestAuditRecordsNeverContainPlaintext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 2})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}
	if _, err := f.svc.CloseAudit(ctx, CloseAuditInput{KeyName: "payments", AuditID: "audit-1"}); err != nil {
		t.Fatalf("close: %v", err)
	}
	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 2, Version: 1})

	// 持久化的审计相关结构（含问题记录、回报、注册表）不得出现明文。
	st, err := f.store.Get(ctx, "payments")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	for _, probe := range []string{auditProbeSecret, auditProbeSecret + "-v2"} {
		if strings.Contains(fmt.Sprintf("%+v", st), probe) {
			t.Fatalf("plaintext leaked into audit storage: %q", probe)
		}
	}

	// 审计事件不得出现明文。
	for _, ev := range f.audit.Events() {
		if blob := fmt.Sprintf("%+v", ev); strings.Contains(blob, auditProbeSecret) {
			t.Fatalf("plaintext leaked into audit event: %+v", ev)
		}
	}

	// 查询视图的文本形式同样不得携带明文。
	a, err := f.svc.GetAudit(ctx, "payments", "audit-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	view, err := f.svc.GetServiceAuditView(ctx, "payments", "audit-1", "billing")
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	for _, blob := range []string{fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", view)} {
		if strings.Contains(blob, auditProbeSecret) {
			t.Fatalf("plaintext leaked into audit query view")
		}
	}

	// 审计相关错误消息也不得泄漏明文。
	_, e1 := f.svc.CreateAudit(ctx, CreateAuditInput{KeyName: "payments", AuditID: "audit-1", Services: nil, Deadline: time.Now()})
	_, e2 := f.svc.GetAudit(ctx, "missing", "audit-1")
	e3 := f.svc.ReportInstance(ctx, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 0, Version: 0})
	for _, e := range []error{e1, e2, e3} {
		if e == nil {
			continue
		}
		if strings.Contains(e.Error(), auditProbeSecret) {
			t.Fatalf("plaintext leaked in audit error: %v", e)
		}
	}
}

// 并发回报竞态：多个实例/部署并发回报时 CAS 保证结论一致、无丢失更新。
func TestConcurrentInstanceReportsRace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setupAuditedKey(t, f)

	doReport(t, f, ReportInstanceInput{KeyName: "payments", Service: "billing", InstanceID: "b-1", DeployGeneration: 1, Version: 1})
	if _, err := f.svc.CreateAudit(ctx, CreateAuditInput{
		KeyName: "payments", AuditID: "audit-1",
		Services: []string{"billing"}, Deadline: auditDeadline(f),
	}); err != nil {
		t.Fatalf("create audit: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			version := 2
			gen := int64(2 + i%3) // 2,3,4 三个部署代号并发
			if i%5 == 0 {
				version = 1 // 部分回报为旧版本
			}
			_ = f.svc.ReportInstance(ctx, ReportInstanceInput{
				KeyName: "payments", Service: "billing", InstanceID: "b-1",
				DeployGeneration: gen, Version: version,
			})
		}(i)
	}
	wg.Wait()

	a := getAudit(t, f)
	res := serviceResult(a, "billing")
	inst := res.Incomplete
	if len(res.Complete)+len(inst) != 1 {
		t.Fatalf("exactly one tracked instance expected: complete=%d incomplete=%d", len(res.Complete), len(inst))
	}
	// 最终结论必须等于注册表中最大部署代号的版本（单一事实来源，无撕裂状态）。
	st, _ := f.store.Get(ctx, "payments")
	reg := st.Instances["billing"]["b-1"]
	var gotVersion int
	if len(res.Complete) == 1 {
		gotVersion = res.Complete[0].LastVersion
	} else {
		gotVersion = inst[0].LastVersion
		if inst[0].LastGeneration != reg.DeployGeneration {
			t.Fatalf("generation mismatch: audit=%d registry=%d", inst[0].LastGeneration, reg.DeployGeneration)
		}
	}
	if gotVersion != reg.Version {
		t.Fatalf("version mismatch: audit=%d registry=%d", gotVersion, reg.Version)
	}
}
