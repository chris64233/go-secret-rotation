package secretrotation

import (
	"crypto/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- 查找与幂等 -------------------------------------------------------------

func findAudit(st *KeyState, id string) *auditState {
	for _, a := range st.Audits {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// auditCreateMatches 判断相同审计号的重放是否与首次参数一致：
// 秘密标识（KeyState 自身）、冻结服务集合、截止时间必须完全相同。
func auditCreateMatches(a *auditState, in *CreateAuditInput) bool {
	if !a.Deadline.Equal(in.Deadline) {
		return false
	}
	return equalSet(a.Services, in.Services)
}

func instanceFingerprint(service, instance string, generation int64, version int) string {
	return service + "|" + instance + "|g" + itoa64(generation) + "|v" + itoa(version)
}

func auditInstanceKey(service, instance string) string {
	return service + "|" + instance
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func joinInts(list []int) string {
	if len(list) == 0 {
		return "-"
	}
	parts := make([]string, len(list))
	for i, v := range list {
		parts[i] = "v" + itoa(v)
	}
	return strings.Join(parts, ",")
}

// --- 注册表与最近回报 ---------------------------------------------------------

// appendRecentReport 在服务的最近回报列表头部插入一条，并裁剪长度。
func (s *Service) appendRecentReport(st *KeyState, r *instanceReportState) {
	list := st.AuditReports[r.Service]
	list = append([]*instanceReportState{r}, list...)
	if len(list) > maxAuditReportsPerService {
		list = list[:maxAuditReportsPerService]
	}
	st.AuditReports[r.Service] = list
}

// appendAuditIssue 为结案后发现的旧版本实例追加问题记录。
func (s *Service) appendAuditIssue(st *KeyState, a *auditState, in ReportInstanceInput, now time.Time) {
	var b [6]byte
	_, _ = rand.Read(b[:])
	issue := &auditIssueState{
		ID:               "issue-" + a.ID + "-" + hex8(b[:]),
		DiscoveredAt:     now,
		Service:          in.Service,
		InstanceID:       in.InstanceID,
		DeployGeneration: in.DeployGeneration,
		Version:          in.Version,
		Detail:           "instance still on revoked version after audit close",
	}
	a.Issues = append(a.Issues, issue)
}

func issueExists(a *auditState, instance string, generation int64, version int) bool {
	for _, is := range a.Issues {
		if is.InstanceID == instance && is.DeployGeneration == generation && is.Version == version {
			return true
		}
	}
	return false
}

// --- 达标判定 ----------------------------------------------------------------

// instanceComplete 是审计视角的达标判定：
// 快照实例 + 有回报 + 截止前到达 + 当前部署回报版本恰好等于安全版本。
// 审计开始后新出现的实例（InSnapshot=false）永远不达标。
func instanceComplete(a *auditState, ai *auditInstanceState) bool {
	if !ai.InSnapshot {
		return false
	}
	if ai.LastReportAt.IsZero() {
		return false
	}
	if ai.LastReportLate {
		return false
	}
	return ai.LastVersion == a.SafeVersion
}

// instanceEffectiveComplete 给出查询时的达标状态：结案后以冻结结论为准，
// 进行中按当前回报实时计算。
func instanceEffectiveComplete(a *auditState, ai *auditInstanceState) bool {
	if a.Status == AuditClosed {
		return ai.CompleteWhenClosed
	}
	return instanceComplete(a, ai)
}

func auditAllComplete(a *auditState) bool {
	// 必须覆盖清单内每个服务：没有任何快照实例、或存在任一不达标快照
	// 实例的服务都视为不达标。审计开始后新出现的实例（InSnapshot=false）
	// 不影响“快照是否全部完成”，但会出现在未达标列表中。
	snapshotCount := map[string]int{}
	completeCount := map[string]int{}
	for _, ai := range a.Instances {
		if !ai.InSnapshot {
			continue
		}
		snapshotCount[ai.Service]++
		if instanceComplete(a, ai) {
			completeCount[ai.Service]++
		}
	}
	for _, svc := range a.Services {
		if snapshotCount[svc] == 0 || completeCount[svc] != snapshotCount[svc] {
			return false
		}
	}
	return true
}

func countComplete(a *auditState) int {
	n := 0
	for _, ai := range a.Instances {
		if ai.InSnapshot && instanceComplete(a, ai) {
			n++
		}
	}
	return n
}

// countOutstanding 统计仍未达标实例数（含审计开始后新出现的实例）。
func countOutstanding(a *auditState) int {
	n := 0
	for _, ai := range a.Instances {
		if !instanceComplete(a, ai) {
			n++
		}
	}
	return n
}

// --- 视图转换 ----------------------------------------------------------------

func auditInstanceInfo(a *auditState, ai *auditInstanceState) InstanceAuditInfo {
	return InstanceAuditInfo{
		Service:        ai.Service,
		InstanceID:     ai.InstanceID,
		InSnapshot:     ai.InSnapshot,
		LastGeneration: ai.LastGeneration,
		LastVersion:    ai.LastVersion,
		LastReportAt:   ai.LastReportAt,
		Late:           ai.LastReportLate,
		Complete:       instanceEffectiveComplete(a, ai),
	}
}

func reportToInfo(r *instanceReportState, inSnapshot bool) InstanceAuditInfo {
	return InstanceAuditInfo{
		Service:        r.Service,
		InstanceID:     r.InstanceID,
		InSnapshot:     inSnapshot,
		LastGeneration: r.DeployGeneration,
		LastVersion:    r.Version,
		LastReportAt:   r.ReportedAt,
	}
}

func auditInfo(keyName string, a *auditState) *AuditInfo {
	out := &AuditInfo{
		AuditID:         a.ID,
		KeyName:         keyName,
		Status:          a.Status,
		Services:        cloneStrings(a.Services),
		SafeVersion:     a.SafeVersion,
		RevokedVersions: cloneInts(a.RevokedVersions),
		StartedAt:       a.StartedAt,
		Deadline:        a.Deadline,
		ClosedAt:        a.ClosedAt,
		FullyComplete:   a.FullyComplete,
	}

	byService := map[string]*ServiceAuditInfo{}
	for _, svc := range a.Services {
		byService[svc] = &ServiceAuditInfo{
			Name: svc, SafeVersion: a.SafeVersion,
			RevokedVersions: cloneInts(a.RevokedVersions),
		}
	}
	keys := make([]string, 0, len(a.Instances))
	for k := range a.Instances {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ai := a.Instances[k]
		svc := byService[ai.Service]
		if svc == nil {
			continue
		}
		info := auditInstanceInfo(a, ai)
		if instanceEffectiveComplete(a, ai) {
			svc.Complete = append(svc.Complete, info)
		} else {
			svc.Incomplete = append(svc.Incomplete, info)
		}
	}
	for _, svcName := range a.Services {
		out.ServiceResults = append(out.ServiceResults, *byService[svcName])
	}
	for _, is := range a.Issues {
		out.Issues = append(out.Issues, AuditIssue{
			ID: is.ID, DiscoveredAt: is.DiscoveredAt,
			Service: is.Service, InstanceID: is.InstanceID,
			DeployGeneration: is.DeployGeneration, Version: is.Version,
			Detail: is.Detail,
		})
	}
	return out
}
