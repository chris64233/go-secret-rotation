package secretrotation

import (
	"context"
	"crypto/rand"
	"sort"
	"sync"
	"time"
)

// maxCASRetries 限制单个操作因并发冲突重试的次数，超过则返回内部错误。
const maxCASRetries = 100

// Clock 允许测试替换时间源。
type Clock func() time.Time

// Service 编排密钥版本、轮换确认、激活/宽限期与受控读取。
// 一个 Service 实例可被多个 goroutine 并发使用；跨进程并发安全由
// Store 的 CompareAndSwap 语义保证。
type Service struct {
	store  Store
	cipher Encryptor
	audit  AuditSink
	now    Clock
	// auditIndex 保证审计号与审计请求号在“同一服务实例”范围内跨密钥唯一。
	// 键为审计号或带前缀的请求号，值为密钥名。
	auditMu    sync.Mutex
	auditIndex map[string]string
}

// NewService 构造轮换服务。audit 可为 nil（不写审计）；clock 为 nil 时
// 使用 time.Now。
func NewService(store Store, enc Encryptor, audit AuditSink, clock Clock) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		store:      store,
		cipher:     enc,
		audit:      audit,
		now:        clock,
		auditIndex: map[string]string{},
	}
}

// CreateKeyVersion 建立一个全新密钥及其首个不可变版本（版本号从 1 开始，
// 创建即激活）。后续“新版本”只能通过轮换产生。明文仅经 Encryptor 加密后
// 以密文形态持久化。
func (s *Service) CreateKeyVersion(ctx context.Context, in CreateKeyInput) (*VersionInfo, error) {
	const op = "CreateKeyVersion"
	if in.Name == "" {
		return nil, newError(CodeInvalidArgument, op, "key name is required")
	}
	if len(in.Plaintext) == 0 {
		return nil, newError(CodeInvalidArgument, op, "plaintext must not be empty")
	}
	if in.GracePeriod < 0 {
		return nil, newError(CodeInvalidArgument, op, "grace period must be >= 0")
	}
	if hasDuplicate(in.Readers) {
		return nil, newError(CodeInvalidArgument, op, "readers must be unique")
	}

	now := s.now()
	ciphertext, err := s.cipher.Encrypt(ctx, in.Name, 1, in.Plaintext)
	if err != nil {
		return nil, newError(CodeInternal, op, "encrypt initial version failed")
	}
	st := &KeyState{
		Name:          in.Name,
		GracePeriod:   in.GracePeriod,
		Readers:       sortedCopy(in.Readers),
		ActiveVersion: 1,
		KeyRequests:   map[string]string{},
		Versions: []*versionState{{
			Number:      1,
			Status:      VersionActive,
			Ciphertext:  ciphertext,
			CreatedAt:   now,
			ActivatedAt: now,
		}},
	}
	if err := s.store.CompareAndSwap(ctx, nil, st); err != nil {
		if err == ErrCASConflict {
			return nil, newError(CodeAlreadyExists, op, "key already exists: "+in.Name)
		}
		return nil, newError(CodeInternal, op, "persist key failed")
	}
	s.writeAudit(ctx, AuditEvent{
		Time: now, KeyName: in.Name, Version: 1, Action: "key_created",
		Detail: "initial version active",
	})
	return versionInfo(st.Versions[0]), nil
}

// StartRotation 发起轮换：产生一个 pending 的不可变新版本，并冻结本次必须
// 确认的消费者集合快照与截止时刻。同一密钥同一时刻只允许一个未终结轮换；
// 相同 RequestID 重放返回同一轮换，若重放参数（快照集合或超时）与首次不同
// 则报 CodeConflict。
func (s *Service) StartRotation(ctx context.Context, in StartRotationInput) (*RotationInfo, error) {
	const op = "StartRotation"
	if in.KeyName == "" {
		return nil, newError(CodeInvalidArgument, op, "key name is required")
	}
	if len(in.NewPlaintext) == 0 {
		return nil, newError(CodeInvalidArgument, op, "plaintext must not be empty")
	}
	if in.Policy.Timeout < 0 {
		return nil, newError(CodeInvalidArgument, op, "timeout must be >= 0")
	}
	if hasDuplicate(in.Policy.RequiredConsumers) {
		return nil, newError(CodeInvalidArgument, op, "required consumers must be unique")
	}

	var info *RotationInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		if in.RequestID != "" {
			if id, ok := st.KeyRequests[in.RequestID]; ok {
				r := findRotation(st, id)
				if r != nil && !startMatches(r, &in) {
					return nil, false, newError(CodeConflict, op, "request id already used with different parameters")
				}
				info = rotationInfo(r)
				return nil, false, nil
			}
		}
		if st.PendingRotation != "" {
			return nil, false, newError(CodeFailedPrecondition, op, "a rotation is already in progress")
		}

		newNumber := len(st.Versions) + 1
		ciphertext, encErr := s.cipher.Encrypt(ctx, in.KeyName, newNumber, in.NewPlaintext)
		if encErr != nil {
			return nil, false, newError(CodeInternal, op, "encrypt new version failed")
		}
		now := s.now()
		st.Versions = append(st.Versions, &versionState{
			Number:     newNumber,
			Status:     VersionPending,
			Ciphertext: ciphertext,
			CreatedAt:  now,
		})
		r := &rotationState{
			ID:             newRotationID(in.KeyName, newNumber, now),
			Status:         RotationPending,
			PendingVersion: newNumber,
			Required:       sortedCopy(in.Policy.RequiredConsumers),
			Acks:           nil,
			AckRequests:    map[string]string{},
			Requests:       map[string]string{},
			CreatedAt:      now,
		}
		if in.Policy.Timeout > 0 {
			r.Deadline = now.Add(in.Policy.Timeout)
		}
		st.Rotations = append(st.Rotations, r)
		st.PendingRotation = r.ID
		if in.RequestID != "" {
			st.KeyRequests[in.RequestID] = r.ID
			r.Requests[in.RequestID] = "start"
		}
		info = rotationInfo(r)
		return auditEvents{{
			Time: now, KeyName: in.KeyName, RotationID: r.ID, Version: newNumber,
			Action: "rotation_started",
			Detail: "required=" + joinList(r.Required) + maybeDeadline(r.Deadline),
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Acknowledge 记录某个消费者“已加载待激活版本”的确认。
//
// 幂等与冲突规则：
//   - 确认以“消费者 + 轮换”为幂等键：同一消费者重复确认直接返回当前轮换
//     状态，不会重复计数、不推进状态之外的任何东西；
//   - 同一 RequestID 被不同内容（不同消费者或不同加载版本）复用时返回
//     CodeConflict；相同内容重放安全返回；
//   - 消费者不在发起时冻结的快照集合内 -> CodePermissionDenied；
//   - 加载版本号与待激活版本不一致 -> CodeInvalidArgument；
//   - 轮换已处于终态后的迟到确认 -> CodeFailedPrecondition。
func (s *Service) Acknowledge(ctx context.Context, in AcknowledgeInput) (*RotationInfo, error) {
	const op = "Acknowledge"
	if in.KeyName == "" || in.RotationID == "" || in.Consumer == "" {
		return nil, newError(CodeInvalidArgument, op, "key name, rotation id and consumer are required")
	}
	if in.LoadedVersion <= 0 {
		return nil, newError(CodeInvalidArgument, op, "loaded version must be positive")
	}

	var info *RotationInfo
	err := s.casLoop(ctx, op, in.KeyName, func(st *KeyState) (auditEvents, bool, error) {
		r := findRotation(st, in.RotationID)
		if r == nil {
			return nil, false, newError(CodeNotFound, op, "rotation not found: "+in.RotationID)
		}
		if in.RequestID != "" {
			if fp, ok := r.AckRequests[in.RequestID]; ok && fp != ackFingerprint(in.Consumer, in.LoadedVersion) {
				return nil, false, newError(CodeConflict, op, "request id already used with different acknowledgement content")
			}
		}
		if !contains(r.Required, in.Consumer) {
			return nil, false, newError(CodePermissionDenied, op, "consumer is not a member of the frozen rotation snapshot")
		}
		if in.LoadedVersion != r.PendingVersion {
			return nil, false, newError(CodeInvalidArgument, op, "loaded version does not match the pending version")
		}
		if r.Status.isTerminal() {
			// 迟到确认：显式拒绝，绝不推进任何状态。
			return nil, false, newError(CodeFailedPrecondition, op, "rotation already in terminal state: "+string(r.Status))
		}
		if contains(r.Acks, in.Consumer) {
			// 消费者+轮换幂等：重复确认安全返回。
			info = rotationInfo(r)
			return nil, false, nil
		}

		now := s.now()
		r.Acks = append(r.Acks, in.Consumer)
		sort.Strings(r.Acks)
		if in.RequestID != "" {
			r.AckRequests[in.RequestID] = ackFingerprint(in.Consumer, in.LoadedVersion)
		}
		info = rotationInfo(r)
		return auditEvents{{
			Time: now, KeyName: in.KeyName, RotationID: r.ID, Version: r.PendingVersion,
			Action: "acknowledged", Actor: in.Consumer,
			Detail: "progress " + itoa(len(r.Acks)) + "/" + itoa(len(r.Required)),
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Activate 在确认门槛达成后原子激活新版本：新版本置为 active，旧 active
// 版本同时进入 grace 宽限期。只有 pending 轮换可激活；重复激活幂等返回；
// 对已取消/已超时轮换的激活返回 CodeFailedPrecondition。
func (s *Service) Activate(ctx context.Context, keyName, rotationID, requestID string) (*RotationInfo, error) {
	const op = "Activate"
	if keyName == "" || rotationID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and rotation id are required")
	}

	var info *RotationInfo
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		r := findRotation(st, rotationID)
		if r == nil {
			return nil, false, newError(CodeNotFound, op, "rotation not found: "+rotationID)
		}
		if requestID != "" {
			if act, ok := r.Requests[requestID]; ok && act != "activate" {
				return nil, false, newError(CodeConflict, op, "request id already used for a different action")
			}
		}
		switch {
		case r.Status == RotationActivated:
			info = rotationInfo(r)
			return nil, false, nil // 激活天然幂等
		case r.Status != RotationPending:
			return nil, false, newError(CodeFailedPrecondition, op, "rotation already in terminal state: "+string(r.Status))
		}
		if missing := missingConsumers(r); len(missing) > 0 {
			return nil, false, newError(CodeFailedPrecondition, op, "acknowledgement threshold not reached, missing: "+joinList(missing))
		}

		now := s.now()
		events := auditEvents{}
		newV := findVersion(st, r.PendingVersion)
		newV.Status = VersionActive
		newV.ActivatedAt = now
		if old := findVersion(st, st.ActiveVersion); old != nil && old.Number != newV.Number {
			if st.GracePeriod > 0 {
				old.Status = VersionGrace
				old.RetireAt = now.Add(st.GracePeriod)
				events = append(events, AuditEvent{
					Time: now, KeyName: keyName, RotationID: r.ID, Version: old.Number,
					Action: "version_grace_started",
					Detail: maybeRetireAt(old.RetireAt),
				})
			} else {
				// 未配置宽限期：旧版本在新版本激活的同一刻立即退役，
				// 此后读取必须失败。
				old.Status = VersionRetired
				events = append(events, AuditEvent{
					Time: now, KeyName: keyName, RotationID: r.ID, Version: old.Number,
					Action: "version_retired", Detail: "no grace period configured",
				})
			}
		}
		st.ActiveVersion = newV.Number
		r.Status = RotationActivated
		r.ActivatedAt = now
		r.EndedAt = now
		st.PendingRotation = ""
		if requestID != "" {
			r.Requests[requestID] = "activate"
		}
		events = append(events, AuditEvent{
			Time: now, KeyName: keyName, RotationID: r.ID, Version: newV.Number,
			Action: "rotation_activated",
		})
		info = rotationInfo(r)
		return events, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// Cancel 取消一次未终结的轮换并废弃其待激活版本。取消为终态；重复取消
// 幂等返回；对已激活/已超时轮换的迟到取消返回 CodeFailedPrecondition，
// 版本状态绝不回退。
func (s *Service) Cancel(ctx context.Context, keyName, rotationID, requestID string) (*RotationInfo, error) {
	const op = "Cancel"
	if keyName == "" || rotationID == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and rotation id are required")
	}

	var info *RotationInfo
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		r := findRotation(st, rotationID)
		if r == nil {
			return nil, false, newError(CodeNotFound, op, "rotation not found: "+rotationID)
		}
		if requestID != "" {
			if act, ok := r.Requests[requestID]; ok && act != "cancel" {
				return nil, false, newError(CodeConflict, op, "request id already used for a different action")
			}
		}
		switch {
		case r.Status == RotationCancelled:
			info = rotationInfo(r)
			return nil, false, nil // 取消幂等
		case r.Status != RotationPending:
			// 已激活或已超时：迟到取消不能改写终态、不能回退版本。
			return nil, false, newError(CodeFailedPrecondition, op, "rotation already in terminal state: "+string(r.Status))
		}

		now := s.now()
		if pv := findVersion(st, r.PendingVersion); pv != nil {
			pv.Status = VersionRetired
		}
		r.Status = RotationCancelled
		r.EndedAt = now
		st.PendingRotation = ""
		if requestID != "" {
			r.Requests[requestID] = "cancel"
		}
		info = rotationInfo(r)
		return auditEvents{{
			Time: now, KeyName: keyName, RotationID: r.ID, Version: r.PendingVersion,
			Action: "rotation_cancelled",
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// ReadSecret 是唯一会返回密钥明文的受控通道：
//   - consumer 必须在读白名单内（未配置白名单时不限制）；
//   - version<=0 读取当前 active 版本；显式版本号只允许读取 active，
//     或尚在 grace 宽限期内的旧版本；pending 版本不可读；
//   - 宽限期结束的旧版本在本次读取中原子转为 retired 并返回 CodeExpired，
//     之后任何读取都失败。
//
// 审计记录只含元数据，不含明文；错误消息同样不含明文或密文片段。
func (s *Service) ReadSecret(ctx context.Context, keyName string, version int, consumer string) (*SecretView, error) {
	const op = "ReadSecret"
	if keyName == "" || consumer == "" {
		return nil, newError(CodeInvalidArgument, op, "key name and consumer are required")
	}

	var view *SecretView
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		if !readerAllowed(st.Readers, consumer) {
			return nil, false, newError(CodePermissionDenied, op, "consumer is not allowed to read this key")
		}
		target := st.ActiveVersion
		if version > 0 {
			target = version
		}
		v := findVersion(st, target)
		if v == nil {
			return nil, false, newError(CodeNotFound, op, "version not found")
		}
		now := s.now()
		switch v.Status {
		case VersionActive:
		case VersionGrace:
			if !v.RetireAt.IsZero() && !now.Before(v.RetireAt) {
				// 宽限期结束：状态先落库为 retired，再把过期错误返回调用方，
				// 保证“此后读取必须失败”。
				v.Status = VersionRetired
				return auditEvents{{
					Time: now, KeyName: keyName, Version: v.Number, Action: "version_retired",
					Actor: consumer, Detail: "grace period ended",
				}}, true, newError(CodeExpired, op, "version grace period ended")
			}
		case VersionPending:
			return nil, false, newError(CodeFailedPrecondition, op, "version has not been activated")
		default:
			return nil, false, newError(CodeExpired, op, "version is retired")
		}

		plaintext, err := s.cipher.Decrypt(ctx, keyName, v.Number, v.Ciphertext)
		if err != nil {
			return nil, false, newError(CodeInternal, op, "decrypt version failed")
		}
		view = &SecretView{KeyName: keyName, Version: v.Number, Plaintext: plaintext, VersionStatus: v.Status}
		return auditEvents{{
			Time: now, KeyName: keyName, Version: v.Number, Action: "secret_read", Actor: consumer,
		}}, false, nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

// ProcessTimeout 对指定密钥执行一次超时处理：若存在已过截止时间但仍
// pending 的轮换，将其终结为 timed_out 并废弃待激活版本。与激活/取消
// 并发时，CAS 保证只有一个终态落库。返回被终结的轮换信息；
// 没有超时发生时返回 nil。
func (s *Service) ProcessTimeout(ctx context.Context, keyName string) (*RotationInfo, error) {
	const op = "ProcessTimeout"
	var timedOut *RotationInfo
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		timedOut = nil
		if st.PendingRotation == "" {
			return nil, false, nil
		}
		r := findRotation(st, st.PendingRotation)
		if r == nil || r.Status != RotationPending || r.Deadline.IsZero() || s.now().Before(r.Deadline) {
			return nil, false, nil
		}
		now := s.now()
		if pv := findVersion(st, r.PendingVersion); pv != nil {
			pv.Status = VersionRetired
		}
		r.Status = RotationTimedOut
		r.EndedAt = now
		st.PendingRotation = ""
		timedOut = rotationInfo(r)
		return auditEvents{{
			Time: now, KeyName: keyName, RotationID: r.ID, Version: r.PendingVersion,
			Action: "rotation_timed_out",
		}}, true, nil
	})
	if err != nil {
		return nil, err
	}
	return timedOut, nil
}

// SweepTimeouts 枚举 Store 中全部密钥并执行超时处理，返回被终结的轮换。
// 适合后台定时任务调用。
func (s *Service) SweepTimeouts(ctx context.Context) ([]RotationInfo, error) {
	const op = "SweepTimeouts"
	names, err := s.store.ListKeys(ctx)
	if err != nil {
		return nil, newError(CodeInternal, op, "list keys failed")
	}
	var out []RotationInfo
	for _, name := range names {
		info, err := s.ProcessTimeout(ctx, name)
		if err != nil {
			return nil, err
		}
		if info != nil {
			out = append(out, *info)
		}
	}
	return out, nil
}

// Status 查询密钥全部版本与轮换的非敏感状态，不返回任何密钥材料。
// 查询过程中会顺带应用已到期的超时与宽限期退役，因此具有状态推进副作用
// （仅推进时间驱动的退役，不影响任何轮换终态竞争）。
func (s *Service) Status(ctx context.Context, keyName string) (*KeyInfo, error) {
	const op = "Status"
	var info *KeyInfo
	err := s.casLoop(ctx, op, keyName, func(st *KeyState) (auditEvents, bool, error) {
		now := s.now()
		events := auditEvents{}
		mutated := false
		if st.PendingRotation != "" {
			if r := findRotation(st, st.PendingRotation); r != nil && r.Status == RotationPending &&
				!r.Deadline.IsZero() && !now.Before(r.Deadline) {
				if pv := findVersion(st, r.PendingVersion); pv != nil {
					pv.Status = VersionRetired
				}
				r.Status = RotationTimedOut
				r.EndedAt = now
				st.PendingRotation = ""
				events = append(events, AuditEvent{
					Time: now, KeyName: keyName, RotationID: r.ID, Version: r.PendingVersion,
					Action: "rotation_timed_out",
				})
				mutated = true
			}
		}
		for _, v := range st.Versions {
			if v.Status == VersionGrace && !v.RetireAt.IsZero() && !now.Before(v.RetireAt) {
				v.Status = VersionRetired
				events = append(events, AuditEvent{
					Time: now, KeyName: keyName, Version: v.Number,
					Action: "version_retired", Detail: "grace period ended",
				})
				mutated = true
			}
		}
		info = keyInfo(st)
		return events, mutated, nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// --- 内部机制 ---------------------------------------------------------------

type auditEvents []AuditEvent

// casLoop 执行“读取-修改-CompareAndSwap”重试。mutate 在状态的深拷贝上
// 工作：返回 commit=false 表示只读或幂等重放，不写库；返回 err 时提前
// 终止；若同时 commit=true 与 err 非 nil（用于宽限期到期这类“先落库再
// 报错”的场景），状态与审计先提交，随后把 err 返回给调用方。
func (s *Service) casLoop(ctx context.Context, op, keyName string, mutate func(st *KeyState) (auditEvents, bool, error)) error {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		current, err := s.store.Get(ctx, keyName)
		if err != nil {
			if err == ErrNotFound {
				return newError(CodeNotFound, op, "key not found: "+keyName)
			}
			return newError(CodeInternal, op, "load key state failed")
		}
		working := cloneKeyState(current)

		events, commit, mErr := mutate(working)
		if mErr != nil && !commit {
			return mErr
		}
		if commit {
			if err := s.store.CompareAndSwap(ctx, current, working); err != nil {
				if err == ErrCASConflict {
					continue
				}
				return newError(CodeInternal, op, "persist key state failed")
			}
		}
		// 只读操作（commit=false，如受控读取）不写状态，但仍记审计；
		// CAS 冲突时上面已 continue，事件随重试重新生成，不会重复落审计。
		for _, ev := range events {
			s.writeAudit(ctx, ev)
		}
		return mErr
	}
	return newError(CodeInternal, op, "too many concurrent conflicts")
}

func (s *Service) writeAudit(ctx context.Context, ev AuditEvent) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Write(ctx, ev)
}

// KeyInfo 是 Status 返回的密钥状态视图（不含密钥材料）。
type KeyInfo struct {
	Name              string
	GracePeriod       time.Duration
	Readers           []string
	ActiveVersion     int
	PendingRotationID string
	Versions          []VersionInfo
	Rotations         []RotationInfo
}

func keyInfo(st *KeyState) *KeyInfo {
	out := &KeyInfo{
		Name:              st.Name,
		GracePeriod:       st.GracePeriod,
		Readers:           cloneStrings(st.Readers),
		ActiveVersion:     st.ActiveVersion,
		PendingRotationID: st.PendingRotation,
	}
	for _, v := range st.Versions {
		out.Versions = append(out.Versions, *versionInfo(v))
	}
	for _, r := range st.Rotations {
		out.Rotations = append(out.Rotations, *rotationInfo(r))
	}
	return out
}

func versionInfo(v *versionState) *VersionInfo {
	return &VersionInfo{
		Number: v.Number, Status: v.Status, CreatedAt: v.CreatedAt,
		ActivatedAt: v.ActivatedAt, RetireAt: v.RetireAt,
	}
}

func rotationInfo(r *rotationState) *RotationInfo {
	return &RotationInfo{
		ID: r.ID, Status: r.Status, PendingVersion: r.PendingVersion,
		RequiredConsumers: cloneStrings(r.Required),
		Acks:              cloneStrings(r.Acks),
		CreatedAt:         r.CreatedAt, Deadline: r.Deadline,
		ActivatedAt: r.ActivatedAt, EndedAt: r.EndedAt,
	}
}

func findRotation(st *KeyState, id string) *rotationState {
	for _, r := range st.Rotations {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func findVersion(st *KeyState, n int) *versionState {
	for _, v := range st.Versions {
		if v.Number == n {
			return v
		}
	}
	return nil
}

func missingConsumers(r *rotationState) []string {
	acked := map[string]struct{}{}
	for _, a := range r.Acks {
		acked[a] = struct{}{}
	}
	var missing []string
	for _, c := range r.Required {
		if _, ok := acked[c]; !ok {
			missing = append(missing, c)
		}
	}
	return missing
}

func readerAllowed(readers []string, consumer string) bool {
	if len(readers) == 0 {
		return true
	}
	return contains(readers, consumer)
}

// ackFingerprint 是确认内容的幂等指纹：消费者 + 其声明加载的版本号。
// 指纹只含元数据，不含密钥材料。
func ackFingerprint(consumer string, loadedVersion int) string {
	return consumer + "#v" + itoa(loadedVersion)
}

// startMatches 判断相同请求号的重放是否与首次发起参数一致。
// 明文在加密后无法回比（AEAD 带随机 IV），故只校验可重现的策略元数据：
// 冻结快照集合与超时时长。
func startMatches(r *rotationState, in *StartRotationInput) bool {
	if !equalSet(r.Required, in.Policy.RequiredConsumers) {
		return false
	}
	wantDeadline := time.Time{}
	if in.Policy.Timeout > 0 {
		wantDeadline = r.CreatedAt.Add(in.Policy.Timeout)
	}
	return r.Deadline.Equal(wantDeadline)
}

func newRotationID(keyName string, version int, now time.Time) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "rot-" + keyName + "-v" + itoa(version) + "-" +
		now.UTC().Format("20060102T150405.000000") + "-" + hex8(b[:])
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func hasDuplicate(list []string) bool {
	seen := map[string]struct{}{}
	for _, v := range list {
		if _, ok := seen[v]; ok {
			return true
		}
		seen[v] = struct{}{}
	}
	return false
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := sortedCopy(a)
	bb := sortedCopy(b)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func sortedCopy(in []string) []string {
	out := cloneStrings(in)
	sort.Strings(out)
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneKeyState(st *KeyState) *KeyState {
	out := &KeyState{
		Name:            st.Name,
		GracePeriod:     st.GracePeriod,
		Readers:         cloneStrings(st.Readers),
		ActiveVersion:   st.ActiveVersion,
		PendingRotation: st.PendingRotation,
		Revision:        st.Revision,
		KeyRequests:     map[string]string{},
	}
	for _, v := range st.Versions {
		cv := *v
		if v.Ciphertext != nil {
			cv.Ciphertext = append([]byte(nil), v.Ciphertext...)
		}
		out.Versions = append(out.Versions, &cv)
	}
	for _, r := range st.Rotations {
		cr := &rotationState{
			ID: r.ID, Status: r.Status, PendingVersion: r.PendingVersion,
			Required: cloneStrings(r.Required), Acks: cloneStrings(r.Acks),
			CreatedAt: r.CreatedAt, Deadline: r.Deadline,
			ActivatedAt: r.ActivatedAt, EndedAt: r.EndedAt,
			AckRequests: map[string]string{}, Requests: map[string]string{},
		}
		for k, v := range r.AckRequests {
			cr.AckRequests[k] = v
		}
		for k, v := range r.Requests {
			cr.Requests[k] = v
		}
		out.Rotations = append(out.Rotations, cr)
	}
	for k, v := range st.KeyRequests {
		out.KeyRequests[k] = v
	}
	for _, a := range st.Audits {
		ca := &auditState{
			AuditID:           a.AuditID,
			Status:            a.Status,
			SafeVersion:       a.SafeVersion,
			Services:          cloneStrings(a.Services),
			Deadline:          a.Deadline,
			CreatedAt:         a.CreatedAt,
			ClosedAt:          a.ClosedAt,
			ClosedSafeVersion: a.ClosedSafeVersion,
			StartRequest:      a.StartRequest,
			CloseRequest:      a.CloseRequest,
			Instances:         map[string]*auditInstanceState{},
			ReportRequests:    map[string]string{},
		}
		for k, v := range a.Instances {
			cv := *v
			ca.Instances[k] = &cv
		}
		for k, v := range a.ReportRequests {
			ca.ReportRequests[k] = v
		}
		for _, is := range a.Issues {
			ci := *is
			ca.Issues = append(ca.Issues, &ci)
		}
		out.Audits = append(out.Audits, ca)
	}
	return out
}

func joinList(list []string) string {
	if len(list) == 0 {
		return "-"
	}
	out := ""
	for i, v := range list {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func maybeDeadline(t time.Time) string {
	if t.IsZero() {
		return "; no timeout"
	}
	return "; deadline=" + t.UTC().Format(time.RFC3339Nano)
}

func maybeRetireAt(t time.Time) string {
	if t.IsZero() {
		return "no grace period"
	}
	return "retire_at=" + t.UTC().Format(time.RFC3339Nano)
}

func hex8(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = h[x>>4]
		out[i*2+1] = h[x&0xf]
	}
	return string(out)
}

// itoa 避免为简单数字转换分散引入 strconv。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
