package secretrotation

import (
	"context"
	"crypto/rand"
	"time"
)

// RevocationInfo 状态查询用的撤销记录（不含任何密钥材料）。
type RevocationInfo struct {
	ID string
	// Version 被撤销的版本号。
	Version int
	Reason  string
	Actor   string
	// CreatedAt 为撤销生效时刻；状态与本记录在同一个 CAS 中原子落库。
	CreatedAt time.Time
	// FallbackVersion 为撤销时选定的临时接替版本；0 表示当时没有仍安全且
	// 未过期的历史版本，读取随即进入“明确失败”状态。
	FallbackVersion int
}

// Revoke 紧急撤销一个疑似泄露、当前仍可能向读取者提供的版本（active 或
// grace）。语义保证：
//
//   - 撤销立即阻止新的读取：被撤销版本置为终态 revoked，显式读取该版本
//     返回 CodeRevoked，且永远不能再次激活或被选为回退目标；
//   - 撤销当前 active 版本时，自动选择“最近一个仍安全且未过期”的历史
//     grace 版本临时接替（读当前版本会返回它并标记 Fallback）；没有合适
//     版本则把服务指针清空，读当前版本明确失败，绝不悄悄切换到任意旧值；
//   - 接替版本随后宽限期到期（或本身被撤销）时停止提供秘密，服务指针清空，
//     不会自行再换到其他版本；
//   - 重复撤销同一版本幂等；相同 RequestID 重放返回同一条撤销记录，
//     同请求号不同参数返回 CodeConflict。
//
// pending 版本不可读，撤销它没有意义，应使用 Cancel；retired 版本已失效，
// 两者均返回 CodeFailedPrecondition。Reason 只允许承载非敏感元数据。
func (s *Service) Revoke(ctx context.Context, in RevokeInput) (*RevocationInfo, error) {
	const op = "Revoke"
	if in.KeyName == "" {
		return nil, newError(CodeInvalidArgument, op, "key name is required")
	}
	if in.Version <= 0 {
		return nil, newError(CodeInvalidArgument, op, "version must be positive")
	}

	var info *RevocationInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		// 请求号幂等：相同 RequestID 必须指向同一次撤销。
		if in.RequestID != "" {
			if id, ok := st.RevocationRequests[in.RequestID]; ok {
				rec := findRevocation(st, id)
				if rec != nil && rec.Version != in.Version {
					return nil, false, newError(CodeConflict, op, "request id already used to revoke a different version")
				}
				info = revocationInfo(rec)
				return nil, false, nil
			}
		}
		// 同版本重复撤销天然幂等：直接返回既有记录，不产生新状态/审计。
		if rec := findRevocationByVersion(st, in.Version); rec != nil {
			info = revocationInfo(rec)
			return nil, false, nil
		}

		v := findVersion(st, in.Version)
		if v == nil {
			return nil, false, newError(CodeNotFound, op, "version not found")
		}
		switch v.Status {
		case VersionActive, VersionGrace:
			// 仅仍可能向读取者提供的版本需要紧急撤销。
		case VersionPending:
			return nil, false, newError(CodeFailedPrecondition, op, "pending version is not readable; cancel its rotation instead")
		default:
			return nil, false, newError(CodeFailedPrecondition, op, "version is already retired")
		}

		now := s.now()
		v.Status = VersionRevoked

		fallback := 0
		events := auditEvents{{
			Time: now, KeyName: in.KeyName, Version: v.Number,
			Action: "version_revoked", Actor: in.Actor,
			Detail: revokeReasonDetail(in.Reason),
		}}

		if v.Number == st.ActiveVersion {
			// 被撤销的是当前版本：选择接替者，或明确进入“无版本可服务”。
			fallback = selectFallback(st, now)
			st.ServingVersion = fallback
			if fallback > 0 {
				events = append(events, AuditEvent{
					Time: now, KeyName: in.KeyName, Version: fallback,
					Action: "fallback_selected", Actor: in.Actor,
					Detail: "temporary replacement for revoked version " + itoa(v.Number),
				})
			} else {
				events = append(events, AuditEvent{
					Time: now, KeyName: in.KeyName, Version: v.Number,
					Action: "serving_halted", Actor: in.Actor,
					Detail: "no safe unexpired historical version available",
				})
			}
		} else if st.ServingVersion == v.Number {
			// 被撤销的正是临时接替版本本身：停止服务，不得自行再选。
			st.ServingVersion = 0
			events = append(events, AuditEvent{
				Time: now, KeyName: in.KeyName, Version: v.Number,
				Action: "serving_halted", Actor: in.Actor,
				Detail: "temporary fallback version revoked",
			})
		}

		rec := &revocationState{
			ID:              newRevocationID(in.KeyName, v.Number, now),
			Version:         v.Number,
			Reason:          in.Reason,
			Actor:           in.Actor,
			CreatedAt:       now,
			FallbackVersion: fallback,
			Requests:        map[string]string{},
		}
		st.Revocations = append(st.Revocations, rec)
		if in.RequestID != "" {
			st.RevocationRequests[in.RequestID] = rec.ID
			rec.Requests[in.RequestID] = "revoke"
		}
		info = revocationInfo(rec)
		return events, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// selectFallback 返回最近一个“仍安全且未过期”的历史版本：状态为 grace
// 且宽限时刻在 now 之后的最高版本号。不存在则返回 0。
// 被撤销（revoked）、已退役（retired）或从未激活（pending）的版本都不参与。
func selectFallback(st *KeyState, now time.Time) int {
	for i := len(st.Versions) - 1; i >= 0; i-- {
		v := st.Versions[i]
		if v.Number >= st.ActiveVersion {
			continue
		}
		if v.Status != VersionGrace {
			continue
		}
		if !v.RetireAt.IsZero() && !now.Before(v.RetireAt) {
			continue
		}
		return v.Number
	}
	return 0
}

func findRevocation(st *KeyState, id string) *revocationState {
	for _, r := range st.Revocations {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func findRevocationByVersion(st *KeyState, version int) *revocationState {
	for _, r := range st.Revocations {
		if r.Version == version {
			return r
		}
	}
	return nil
}

func revocationInfo(r *revocationState) *RevocationInfo {
	if r == nil {
		return nil
	}
	return &RevocationInfo{
		ID: r.ID, Version: r.Version, Reason: r.Reason, Actor: r.Actor,
		CreatedAt: r.CreatedAt, FallbackVersion: r.FallbackVersion,
	}
}

func newRevocationID(keyName string, version int, now time.Time) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "rev-" + keyName + "-v" + itoa(version) + "-" +
		now.UTC().Format("20060102T150405.000000") + "-" + hex8(b[:])
}

func revokeReasonDetail(reason string) string {
	if reason == "" {
		return "reason=-"
	}
	return "reason=" + reason
}
