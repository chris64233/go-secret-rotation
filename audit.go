package secretrotation

import (
	"context"
	"sort"
	"time"
)

// maxAuditReportsPerService 限制每个服务保存的最近回报条数。
const maxAuditReportsPerService = 50

// ReportInstance 接收某个服务实例对“当前实际使用秘密版本”的回报。
//
// 回报会更新全局实例注册表，并被同一秘密下所有进行中的审计观测：
//   - 服务不在某审计的冻结清单内：对该审计无影响；
//   - 部署代号小于审计已记录代号：判定为重部署竞态中的旧部署迟到回报，
//     忽略且不覆盖新部署状态；
//   - 审计开始之后才首次出现的实例：登记但 InSnapshot=false，永不计入完成；
//   - 超过审计截止时间的回报标记为逾期，不能再把实例计入完成。
//
// 审计结案之后收到的回报：结案结论保持冻结；若回报显示实例仍在使用被
// 撤销版本，则追加一条 AuditIssue（按“实例 + 部署代号”去重），绝不改写
// 已经冻结的历史结案。
//
// 幂等：相同 RequestID 重放返回相同结果；请求号被不同内容复用返回
// CodeConflict。回报内容只含版本号等元数据，不含秘密明文或密文。
func (s *Service) ReportInstance(ctx context.Context, in ReportInstanceInput) error {
	const op = "ReportInstance"
	if in.KeyName == "" || in.Service == "" || in.InstanceID == "" {
		return newError(CodeInvalidArgument, op, "key name, service and instance id are required")
	}
	if in.Version <= 0 {
		return newError(CodeInvalidArgument, op, "reported version must be positive")
	}
	if in.DeployGeneration < 0 {
		return newError(CodeInvalidArgument, op, "deploy generation must be >= 0")
	}

	return s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		fingerprint := instanceFingerprint(in.Service, in.InstanceID, in.DeployGeneration, in.Version)
		if in.RequestID != "" {
			if fp, ok := st.AuditRequests[in.RequestID]; ok && fp != "report:"+fingerprint {
				return nil, false, newError(CodeConflict, op, "request id already used with different report content")
			}
		}

		now := s.now()
		events := auditEvents{}
		mutated := false

		// 1) 全局实例注册表：仅接受更新的部署代号，旧部署迟到回报不覆盖。
		reg := st.Instances[in.Service]
		if reg == nil {
			reg = map[string]*instanceReportState{}
			st.Instances[in.Service] = reg
		}
		prev, existed := reg[in.InstanceID]
		switch {
		case !existed:
			reg[in.InstanceID] = &instanceReportState{
				Service: in.Service, InstanceID: in.InstanceID,
				DeployGeneration: in.DeployGeneration, Version: in.Version,
				ReportedAt: now, RequestID: in.RequestID,
			}
			mutated = true
		case in.DeployGeneration > prev.DeployGeneration || prev.ReportedAt.IsZero():
			prev.DeployGeneration = in.DeployGeneration
			prev.Version = in.Version
			prev.ReportedAt = now
			prev.RequestID = in.RequestID
			mutated = true
		case in.DeployGeneration == prev.DeployGeneration:
			if in.Version != prev.Version {
				prev.Version = in.Version
				prev.ReportedAt = now
				prev.RequestID = in.RequestID
				mutated = true
			}
		default:
			// 旧部署代号：重部署竞态中的迟到回报，忽略，不推进任何审计。
			return nil, false, nil
		}

		if mutated {
			s.appendRecentReport(st, &instanceReportState{
				Service: in.Service, InstanceID: in.InstanceID,
				DeployGeneration: in.DeployGeneration, Version: in.Version,
				ReportedAt: now, RequestID: in.RequestID,
			})
			events = append(events, AuditEvent{
				Time: now, KeyName: in.KeyName, Version: in.Version,
				Action: "instance_version_reported", Actor: in.Service,
				Detail: "instance=" + in.InstanceID +
					"; generation=" + itoa64(in.DeployGeneration),
			})
		}

		// 2) 让同一秘密下全部审计观测该回报。
		for _, a := range st.Audits {
			if !contains(a.Services, in.Service) {
				continue
			}
			key := auditInstanceKey(in.Service, in.InstanceID)
			ai, seen := a.Instances[key]
			if !seen {
				// 审计开始之后才出现的实例：登记但永不计入完成。
				ai = &auditInstanceState{
					Service: in.Service, InstanceID: in.InstanceID,
					InSnapshot: false,
				}
				a.Instances[key] = ai
			}
			if in.DeployGeneration < ai.LastGeneration {
				// 重部署竞态：旧部署的迟到回报不能覆盖新部署结论。
				continue
			}
			if a.Status == AuditClosed {
				// 结案后历史结论冻结；仍在用被撤销版本只追加问题记录。
				if in.DeployGeneration >= ai.LastGeneration &&
					containsInt(a.RevokedVersions, in.Version) &&
					!issueExists(a, in.InstanceID, in.DeployGeneration, in.Version) {
					ai.LastGeneration = in.DeployGeneration
					ai.LastVersion = in.Version
					ai.LastReportAt = now
					s.appendAuditIssue(st, a, in, now)
					events = append(events, AuditEvent{
						Time: now, KeyName: in.KeyName, RotationID: a.ID,
						Version: in.Version, Action: "audit_issue_recorded", Actor: in.Service,
						Detail: "instance=" + in.InstanceID + "; post-close revoked version",
					})
					mutated = true
				} else if in.DeployGeneration >= ai.LastGeneration {
					ai.LastGeneration = in.DeployGeneration
					ai.LastVersion = in.Version
					ai.LastReportAt = now
				}
				continue
			}
			// 进行中：按新部署实际版本重新判断，不沿用旧实例“已完成”。
			if in.DeployGeneration > ai.LastGeneration || ai.LastReportAt.IsZero() {
				ai.LastGeneration = in.DeployGeneration
				ai.LastVersion = in.Version
				ai.LastReportAt = now
				ai.LastReportLate = !now.Before(a.Deadline)
				mutated = true
			} else if in.DeployGeneration == ai.LastGeneration && in.Version != ai.LastVersion {
				ai.LastVersion = in.Version
				ai.LastReportAt = now
				ai.LastReportLate = !now.Before(a.Deadline)
				mutated = true
			}
		}

		if in.RequestID != "" {
			st.AuditRequests[in.RequestID] = "report:" + fingerprint
		}
		return events, mutated, nil
	})
}

// CreateAudit 发起一次轮换审计：冻结秘密标识、服务清单、当前安全版本、
// 被撤销版本集合、截止时间与“审计开始时已知实例”的快照。
//
// 审计开始之后新出现的实例以 InSnapshot=false 登记，永远不能算作完成；
// 服务在截止前重新部署时，按新部署代号回报的实际版本重新判断。
//
// 幂等与冲突：相同 AuditID 重复请求返回原结果；同审计号但秘密标识、
// 服务集合或截止时间不同，返回 CodeConflict。审计记录不保存明文秘密。
func (s *Service) CreateAudit(ctx context.Context, in CreateAuditInput) (*AuditInfo, error) {
	const op = "CreateAudit"
	if in.KeyName == "" || in.AuditID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and audit id are required")
	}
	if len(in.Services) == 0 {
		return nil, newError(CodeInvalidArgument, op, "service list must not be empty")
	}
	if hasDuplicate(in.Services) {
		return nil, newError(CodeInvalidArgument, op, "services must be unique")
	}

	var info *AuditInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		if existing := findAudit(st, in.AuditID); existing != nil {
			if !auditCreateMatches(existing, &in) {
				return nil, false, newError(CodeConflict, op, "audit id already used with different secret, services or deadline")
			}
			info = auditInfo(st.Name, existing)
			return nil, false, nil
		}
		// 审计号是调用方分配的全局标识：同一审计号被另一个秘密复用 -> 冲突。
		s.auditMu.Lock()
		owner, occupied := s.auditIndex[in.AuditID]
		s.auditMu.Unlock()
		if occupied && owner != in.KeyName {
			return nil, false, newError(CodeConflict, op, "audit id already used for a different secret")
		}
		if in.RequestID != "" {
			if used, ok := st.AuditRequests[in.RequestID]; ok && used != "create:"+in.AuditID {
				return nil, false, newError(CodeConflict, op, "request id already used for a different audit action")
			}
		}

		safeVersion := st.ActiveVersion
		if safeVersion <= 0 {
			return nil, false, newError(CodeFailedPrecondition, op, "secret has no active safe version")
		}
		var revoked []int
		for _, v := range st.Versions {
			if v.Number < safeVersion && v.Status != VersionPending {
				revoked = append(revoked, v.Number)
			}
		}

		now := s.now()
		a := &auditState{
			ID:              in.AuditID,
			Status:          AuditOpen,
			Services:        sortedCopy(in.Services),
			SafeVersion:     safeVersion,
			RevokedVersions: revoked,
			StartedAt:       now,
			Deadline:        in.Deadline,
			Instances:       map[string]*auditInstanceState{},
			Requests:        map[string]string{},
		}
		// 冻结审计开始时刻的实例快照：仅包含清单内服务的已知实例。
		for _, svc := range a.Services {
			for id, r := range st.Instances[svc] {
				a.Instances[auditInstanceKey(svc, id)] = &auditInstanceState{
					Service:        svc,
					InstanceID:     id,
					InSnapshot:     true,
					LastGeneration: r.DeployGeneration,
					LastVersion:    r.Version,
					LastReportAt:   r.ReportedAt,
					LastReportLate: !r.ReportedAt.Before(a.Deadline),
				}
			}
		}
		st.Audits = append(st.Audits, a)
		s.auditMu.Lock()
		s.auditIndex[in.AuditID] = in.KeyName
		s.auditMu.Unlock()
		if in.RequestID != "" {
			st.AuditRequests[in.RequestID] = "create:" + in.AuditID
			a.Requests[in.RequestID] = "create"
		}
		info = auditInfo(st.Name, a)
		return auditEvents{{
			Time: now, KeyName: in.KeyName, RotationID: in.AuditID,
			Version: safeVersion, Action: "audit_started",
			Detail: "services=" + joinList(a.Services) +
				"; safe=v" + itoa(safeVersion) +
				"; revoked=" + joinInts(revoked) +
				"; snapshot_instances=" + itoa(len(a.Instances)) +
				"; deadline=" + in.Deadline.UTC().Format(time.RFC3339Nano),
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// CloseAudit 对审计结案。只有全部服务的全部快照实例都在截止前回报了
// 当前安全版本时才允许在截止时间之前结案；只要仍有快照实例停留在被撤销
// 版本，截止前的结案请求会被拒绝（CodeFailedPrecondition），旧版本不能
// 提前结案。到达截止时间后允许以“未全部完成”结案。结案是不可变快照：
// 之后发现旧版本实例只会追加问题记录。重复结案幂等返回冻结结论。
func (s *Service) CloseAudit(ctx context.Context, in CloseAuditInput) (*AuditInfo, error) {
	const op = "CloseAudit"
	if in.KeyName == "" || in.AuditID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and audit id are required")
	}

	var info *AuditInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		a := findAudit(st, in.AuditID)
		if a == nil {
			return nil, false, newError(CodeNotFound, op, "audit not found: "+in.AuditID)
		}
		if in.RequestID != "" {
			if act, ok := a.Requests[in.RequestID]; ok && act != "close" {
				return nil, false, newError(CodeConflict, op, "request id already used for a different action")
			}
			if used, ok := st.AuditRequests[in.RequestID]; ok && used != "close:"+in.AuditID {
				return nil, false, newError(CodeConflict, op, "request id already used for a different audit action")
			}
		}
		if a.Status == AuditClosed {
			info = auditInfo(st.Name, a)
			return nil, false, nil
		}

		now := s.now()
		if now.Before(a.Deadline) && !auditAllComplete(a) {
			var outstanding []string
			for _, ai := range a.Instances {
				if ai.InSnapshot && !instanceComplete(a, ai) {
					outstanding = append(outstanding, ai.Service+"/"+ai.InstanceID)
				}
			}
			sort.Strings(outstanding)
			return nil, false, newError(CodeFailedPrecondition, op,
				"audit cannot close before deadline while instances are not on the safe version: "+joinList(outstanding))
		}
		a.ClosedAt = now
		a.Status = AuditClosed
		a.FullyComplete = auditAllComplete(a)
		for _, ai := range a.Instances {
			ai.CompleteWhenClosed = instanceComplete(a, ai)
		}
		if in.RequestID != "" {
			a.Requests[in.RequestID] = "close"
			st.AuditRequests[in.RequestID] = "close:" + in.AuditID
		}
		info = auditInfo(st.Name, a)
		return auditEvents{{
			Time: now, KeyName: in.KeyName, RotationID: a.ID,
			Version: a.SafeVersion, Action: "audit_closed",
			Detail: "fully_complete=" + boolStr(a.FullyComplete) +
				"; complete=" + itoa(countComplete(a)) +
				"; outstanding=" + itoa(countOutstanding(a)),
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// GetAudit 查询一次审计的非敏感视图：各服务的当前安全版本、被撤销版本、
// 已完成与仍未达标（含审计开始后新出现）的实例，以及结案后追加的问题
// 记录。视图不包含任何秘密明文或密文。
func (s *Service) GetAudit(ctx context.Context, keyName, auditID string) (*AuditInfo, error) {
	const op = "GetAudit"
	if keyName == "" || auditID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and audit id are required")
	}
	var info *AuditInfo
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		a := findAudit(st, auditID)
		if a == nil {
			return nil, false, newError(CodeNotFound, op, "audit not found: "+auditID)
		}
		info = auditInfo(st.Name, a)
		return nil, false, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// GetServiceAuditView 按服务查看审计：返回该服务的安全版本、被撤销版本、
// 最近回报以及仍未达标的实例（含审计开始后新出现的实例）。
// 结案后查询的达标状态以结案冻结结论为准；进行中则按当前回报实时判断。
func (s *Service) GetServiceAuditView(ctx context.Context, keyName, auditID, service string) (*ServiceAuditView, error) {
	const op = "GetServiceAuditView"
	if keyName == "" || auditID == "" || service == "" {
		return nil, newError(CodeInvalidArgument, op, "key name, audit id and service are required")
	}
	var view *ServiceAuditView
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		a := findAudit(st, auditID)
		if a == nil {
			return nil, false, newError(CodeNotFound, op, "audit not found: "+auditID)
		}
		if !contains(a.Services, service) {
			return nil, false, newError(CodeNotFound, op, "service is not a member of the frozen audit service list")
		}
		v := &ServiceAuditView{
			KeyName: keyName, AuditID: auditID, Service: service,
			SafeVersion:     a.SafeVersion,
			RevokedVersions: cloneInts(a.RevokedVersions),
		}
		// 最近回报：全局回报通道中该服务的记录（新的在前）。
		for _, r := range st.AuditReports[service] {
			v.RecentReports = append(v.RecentReports, reportToInfo(r, false))
		}
		// 仍未达标实例：以审计观测集合为准（含审计开始后新出现实例）。
		var keys []string
		for k, ai := range a.Instances {
			if ai.Service == service {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			ai := a.Instances[k]
			if !instanceEffectiveComplete(a, ai) {
				v.Outstanding = append(v.Outstanding, auditInstanceInfo(a, ai))
			}
		}
		view = v
		return nil, false, nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}
