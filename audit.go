package secretrotation

import (
	"context"
	"crypto/rand"
	"time"
)

// 审计请求号在跨密钥索引中的键前缀，避免与审计号空间碰撞。
const auditRequestPrefix = "req:"

// StartAudit 发起一次针对紧急撤销/回退的轮换审计：
//   - 发起时固定秘密标识（密钥名）、服务清单、当前安全版本与截止时刻；
//   - 审计开始之后新出现的实例不会被当作“已完成”，必须按其截止前的
//     实际版本回报重新判断；
//   - 相同审计号重复请求返回原审计结果；相同审计号但秘密标识、服务集合
//     或截止时刻不同，返回 CodeConflict；
//   - 相同请求号被不同审计内容复用同样返回 CodeConflict。
//
// 审计记录只保存秘密标识与版本号等元数据，绝不保存明文或密文。
func (s *Service) StartAudit(ctx context.Context, in StartAuditInput) (*AuditInfo, error) {
	const op = "StartAudit"
	if in.KeyName == "" || in.AuditID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and audit id are required")
	}
	if len(in.Services) == 0 {
		return nil, newError(CodeInvalidArgument, op, "service list must not be empty")
	}
	if hasDuplicate(in.Services) {
		return nil, newError(CodeInvalidArgument, op, "services must be unique")
	}

	// 跨密钥的审计号/请求号冲突预检（同一 Service 实例范围内）。
	s.auditMu.Lock()
	if kn, ok := s.auditIndex[in.AuditID]; ok && kn != in.KeyName {
		s.auditMu.Unlock()
		return nil, newError(CodeConflict, op, "audit id already used for a different secret")
	}
	if in.RequestID != "" {
		rk := auditRequestPrefix + in.RequestID
		if val, ok := s.auditIndex[rk]; ok && val != in.KeyName+"#"+in.AuditID {
			s.auditMu.Unlock()
			return nil, newError(CodeConflict, op, "request id already used for a different audit")
		}
	}
	s.auditMu.Unlock()

	services := sortedCopy(in.Services)
	var info *AuditInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		if a := findAudit(st, in.AuditID); a != nil {
			if !auditStartMatches(a, in) {
				return nil, false, newError(CodeConflict, op, "audit id already used with different services or deadline")
			}
			if in.RequestID != "" && a.StartRequest != "" && a.StartRequest != in.RequestID {
				return nil, false, newError(CodeConflict, op, "audit id already used with a different request id")
			}
			info = auditInfoView(st, a)
			return nil, false, nil // 相同审计号重放：返回原结果
		}
		if in.RequestID != "" {
			for _, ex := range st.Audits {
				if ex.StartRequest == in.RequestID {
					return nil, false, newError(CodeConflict, op, "request id already used for a different audit")
				}
			}
		}
		if st.ActiveVersion <= 0 {
			return nil, false, newError(CodeFailedPrecondition, op, "secret has no active version to pin as safe version")
		}
		now := s.now()
		if !in.Deadline.After(now) {
			return nil, false, newError(CodeInvalidArgument, op, "deadline must be in the future")
		}
		a := &auditState{
			AuditID:        in.AuditID,
			Status:         AuditOpen,
			SafeVersion:    st.ActiveVersion,
			Services:       services,
			Deadline:       in.Deadline,
			CreatedAt:      now,
			Instances:      map[string]*auditInstanceState{},
			ReportRequests: map[string]string{},
			StartRequest:   in.RequestID,
		}
		st.Audits = append(st.Audits, a)
		info = auditInfoView(st, a)
		return auditEvents{{
			Time: now, KeyName: in.KeyName, Version: a.SafeVersion,
			Action: "audit_started", Detail: auditStartDetail(a),
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}

	// CAS 成功后登记跨密钥索引；CAS 冲突重试或提交失败时不会走到这里，
	// 因而不会留下指向未提交审计的索引项。
	s.auditMu.Lock()
	s.auditIndex[in.AuditID] = in.KeyName
	if in.RequestID != "" {
		s.auditIndex[auditRequestPrefix+in.RequestID] = in.KeyName + "#" + in.AuditID
	}
	s.auditMu.Unlock()
	return info, nil
}

// ReportInstance 上报某服务的某实例当前实际运行的版本：
//   - 服务必须在发起时冻结的清单内，否则 CodePermissionDenied；
//   - 版本必须是该密钥已存在且非 pending 的版本，否则 CodeInvalidArgument；
//   - 截止前收到的回报按“同一实例最新一次”覆盖，结案时按实际版本现算，
//     重部署的新实例不会沿用旧实例的“已完成”结论；
//   - 截止之后才到的回报照常留痕，但 BeforeDeadline=false，不计入达标；
//   - 审计结案之后的回报不再改写结案：若回报的是已撤销（旧）版本，
//     追加一条新的问题记录；相同请求号重放返回原结果，内容变化返回冲突。
func (s *Service) ReportInstance(ctx context.Context, in ReportInstanceInput) (*AuditInfo, error) {
	const op = "ReportInstance"
	if in.KeyName == "" || in.AuditID == "" || in.Service == "" || in.Instance == "" {
		return nil, newError(CodeInvalidArgument, op, "key name, audit id, service and instance are required")
	}
	if in.Version <= 0 {
		return nil, newError(CodeInvalidArgument, op, "version must be positive")
	}

	var info *AuditInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		a := findAudit(st, in.AuditID)
		if a == nil {
			return nil, false, newError(CodeNotFound, op, "audit not found: "+in.AuditID)
		}
		fp := reportFingerprint(in)
		if in.RequestID != "" {
			if prev, ok := a.ReportRequests[in.RequestID]; ok && prev != fp {
				return nil, false, newError(CodeConflict, op, "request id already used with different report content")
			}
		}
		if !contains(a.Services, in.Service) {
			return nil, false, newError(CodePermissionDenied, op, "service is not a member of the frozen audit service list")
		}
		v := findVersion(st, in.Version)
		if v == nil {
			return nil, false, newError(CodeInvalidArgument, op, "reported version does not exist")
		}
		if v.Status == VersionPending {
			return nil, false, newError(CodeInvalidArgument, op, "reported version has not been activated")
		}
		now := s.now()

		// 结案之后：历史不可变，只允许追加问题记录。
		if a.Status == AuditClosed {
			events := auditEvents{}
			if in.Version < a.ClosedSafeVersion &&
				!issueExists(a, in.Service, in.Instance, in.Version) {
				iss := &auditIssue{
					ID:       newIssueID(in.AuditID, now),
					Service:  in.Service,
					Instance: in.Instance,
					Version:  in.Version,
					FoundAt:  now,
				}
				a.Issues = append(a.Issues, iss)
				if in.RequestID != "" {
					a.ReportRequests[in.RequestID] = fp
				}
				events = append(events, AuditEvent{
					Time: now, KeyName: in.KeyName, RotationID: auditRotationRef(a.AuditID),
					Version: in.Version, Action: "audit_issue_found",
					Actor:  in.Service + "/" + in.Instance,
					Detail: "revoked version observed after audit closed; issue=" + iss.ID,
				})
			}
			info = auditInfoView(st, a)
			return events, len(events) > 0, nil
		}

		// 审计窗口内：以实例为键保存最新回报，达标结论始终在读取时现算。
		key := instanceKey(in.Service, in.Instance)
		a.Instances[key] = &auditInstanceState{
			Service:    in.Service,
			Instance:   in.Instance,
			Version:    in.Version,
			ReportedAt: now,
			Replaces:   in.Replaces,
		}
		if in.RequestID != "" {
			a.ReportRequests[in.RequestID] = fp
		}
		info = auditInfoView(st, a)
		late := ""
		if now.After(a.Deadline) {
			late = "; after deadline"
		}
		return auditEvents{{
			Time: now, KeyName: in.KeyName, RotationID: auditRotationRef(a.AuditID),
			Version: in.Version, Action: "audit_instance_reported",
			Actor:  in.Service + "/" + in.Instance,
			Detail: "v" + itoa(in.Version) + late,
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// CloseAudit 在截止时间之后结案：
//   - 未到截止时刻调用返回 CodeFailedPrecondition，审计不能提前结案；
//   - 结案时当前 active 必须仍是发起时固定的安全版本；若紧急撤销/再次
//     轮换已经把安全版本推进，旧版本回报不能算作达标，返回
//     CodeFailedPrecondition，需另开审计；
//   - 结案结果（哪些实例达标/未达标）是当时快照，之后不可改写；
//   - 重复结案幂等返回原结果；请求号被其他内容复用返回 CodeConflict。
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
		if a.Status == AuditClosed {
			if in.RequestID != "" && a.CloseRequest != "" && a.CloseRequest != in.RequestID {
				return nil, false, newError(CodeConflict, op, "audit already closed with a different request id")
			}
			info = auditInfoView(st, a)
			return nil, false, nil
		}
		if in.RequestID != "" {
			if a.StartRequest == in.RequestID {
				return nil, false, newError(CodeConflict, op, "request id already used for a different action")
			}
			if _, ok := a.ReportRequests[in.RequestID]; ok {
				return nil, false, newError(CodeConflict, op, "request id already used for a different action")
			}
		}
		now := s.now()
		if now.Before(a.Deadline) {
			return nil, false, newError(CodeFailedPrecondition, op, "audit deadline has not been reached")
		}
		if st.ActiveVersion != a.SafeVersion {
			return nil, false, newError(CodeFailedPrecondition, op,
				"current safe version differs from the pinned version; start a new audit")
		}

		a.Status = AuditClosed
		a.ClosedAt = now
		a.ClosedSafeVersion = a.SafeVersion
		a.CloseRequest = in.RequestID

		complete, incomplete := tallyInstances(a)
		info = auditInfoView(st, a)
		return auditEvents{{
			Time: now, KeyName: in.KeyName, RotationID: auditRotationRef(a.AuditID),
			Version: a.ClosedSafeVersion, Action: "audit_closed",
			Detail: "complete=" + itoa(complete) + "; incomplete=" + itoa(incomplete),
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// GetAudit 查询审计的非敏感视图：按服务展示当前安全版本、已撤销版本、
// 最近一次回报，以及仍未达标的实例。返回内容只含秘密标识（密钥名）与
// 版本号，不含任何明文或密文。
func (s *Service) GetAudit(ctx context.Context, keyName, auditID string) (*AuditInfo, error) {
	const op = "GetAudit"
	if keyName == "" || auditID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and audit id are required")
	}
	current, err := s.store.Get(ctx, keyName)
	if err != nil {
		if err == ErrNotFound {
			return nil, newError(CodeNotFound, op, "key not found: "+keyName)
		}
		return nil, newError(CodeInternal, op, "load key state failed")
	}
	a := findAudit(current, auditID)
	if a == nil {
		return nil, newError(CodeNotFound, op, "audit not found: "+auditID)
	}
	return auditInfoView(current, a), nil
}

// --- 审计内部机制 -----------------------------------------------------------

func findAudit(st *KeyState, id string) *auditState {
	for _, a := range st.Audits {
		if a.AuditID == id {
			return a
		}
	}
	return nil
}

func auditStartMatches(a *auditState, in StartAuditInput) bool {
	return equalSet(a.Services, in.Services) && a.Deadline.Equal(in.Deadline)
}

func instanceKey(service, instance string) string {
	return service + "/" + instance
}

func reportFingerprint(in ReportInstanceInput) string {
	return in.Service + "#" + in.Instance + "#v" + itoa(in.Version) + "#" + in.Replaces
}

func issueExists(a *auditState, service, instance string, version int) bool {
	for _, is := range a.Issues {
		if is.Service == service && is.Instance == instance && is.Version == version {
			return true
		}
	}
	return false
}

// auditRotationRef 复用 AuditEvent.RotationID 字段承载审计号，避免为审计
// 扩展事件结构；该字段在这里的语义是“关联流程 ID”。
func auditRotationRef(auditID string) string {
	return "audit:" + auditID
}

func newIssueID(auditID string, now time.Time) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "issue-" + auditID + "-" +
		now.UTC().Format("20060102T150405.000000") + "-" + hex8(b[:])
}

func auditStartDetail(a *auditState) string {
	return "safe=v" + itoa(a.SafeVersion) +
		"; services=" + joinList(a.Services) +
		"; deadline=" + a.Deadline.UTC().Format(time.RFC3339Nano)
}
