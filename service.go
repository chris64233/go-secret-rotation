package secretrotation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Service 是密钥轮换编排服务。所有状态迁移都在同一把互斥锁内完成，
// 保证激活、取消、超时并发时只会产生一个终态。
type Service struct {
	mu    sync.Mutex
	store Store
	enc   *encryptor
	now   func() time.Time

	state *persistedState
}

// Option 用于定制 Service。
type Option func(*Service)

// WithClock 注入时钟，主要用于测试超时与宽限期。
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// NewService 从 store 加载状态并返回服务。masterKey 必须为 32 字节。
func NewService(store Store, masterKey []byte, opts ...Option) (*Service, error) {
	enc, err := newEncryptor(masterKey)
	if err != nil {
		return nil, err
	}
	state, err := store.Load()
	if err != nil {
		return nil, err
	}
	s := &Service{
		store: store,
		enc:   enc,
		now:   time.Now,
		state: state,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// CreateVersion 以 pending 状态创建一个新的不可变版本。明文只存在于本次调用内，
// 落盘的只有密文。
func (s *Service) CreateVersion(ctx context.Context, secretID string, plaintext []byte) (*Version, error) {
	const op = "CreateVersion"
	if secretID == "" {
		return nil, newError(KindInvalidInput, op, "secret id is required")
	}
	if len(plaintext) == 0 {
		return nil, newError(KindInvalidInput, op, "plaintext must not be empty")
	}
	ciphertext, err := s.enc.encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)

	v := &Version{
		ID:         newID("ver"),
		SecretID:   secretID,
		State:      VersionPending,
		Ciphertext: ciphertext,
		CreatedAt:  now,
	}
	s.state.Versions[v.ID] = v
	err = s.persistLocked(AuditEvent{
		ID: newID("evt"), At: now, Type: AuditVersionCreated,
		SecretID: secretID, VersionID: v.ID,
	})
	if err != nil {
		return nil, err
	}
	return cloneVersion(v), nil
}

// StartRotation 针对一个 pending 版本发起轮换，并冻结本次必须确认的消费者快照。
// 同一密钥同一时间只允许一个进行中的轮换。
func (s *Service) StartRotation(ctx context.Context, secretID, toVersionID string, consumers []string, policy RotationPolicy) (*Rotation, error) {
	const op = "StartRotation"
	if secretID == "" || toVersionID == "" {
		return nil, newError(KindInvalidInput, op, "secret id and target version are required")
	}
	if policy.AckTimeout <= 0 {
		return nil, newError(KindInvalidInput, op, "ack timeout must be positive")
	}
	if policy.GracePeriod < 0 {
		return nil, newError(KindInvalidInput, op, "grace period must not be negative")
	}
	snapshot := map[string]bool{}
	for _, c := range consumers {
		if c == "" {
			return nil, newError(KindInvalidInput, op, "consumer id must not be empty")
		}
		snapshot[c] = true
	}
	if len(snapshot) == 0 {
		return nil, newError(KindInvalidInput, op, "at least one consumer is required")
	}
	minAcks := policy.MinAcks
	if minAcks == 0 {
		minAcks = len(snapshot)
	}
	if minAcks < 0 || minAcks > len(snapshot) {
		return nil, newError(KindInvalidInput, op, "min acks out of range")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)

	to, ok := s.state.Versions[toVersionID]
	if !ok || to.SecretID != secretID {
		return nil, newError(KindNotFound, op, "target version not found")
	}
	if to.State != VersionPending {
		return nil, newError(KindInvalidState, op, "target version is not pending")
	}
	for _, r := range s.state.Rotations {
		if r.SecretID == secretID && r.State == RotationCollecting {
			return nil, newError(KindConflict, op, "another rotation is already collecting acks")
		}
	}

	fromVersion := ""
	for _, v := range s.state.Versions {
		if v.SecretID == secretID && v.State == VersionActive {
			fromVersion = v.ID
			break
		}
	}

	r := &Rotation{
		ID:          newID("rot"),
		SecretID:    secretID,
		FromVersion: fromVersion,
		ToVersion:   toVersionID,
		State:       RotationCollecting,
		Consumers:   snapshot,
		MinAcks:     minAcks,
		Acks:        map[string]AckRecord{},
		GracePeriod: policy.GracePeriod,
		Deadline:    now.Add(policy.AckTimeout),
		CreatedAt:   now,
	}
	s.state.Rotations[r.ID] = r
	err := s.persistLocked(AuditEvent{
		ID: newID("evt"), At: now, Type: AuditRotationStarted,
		SecretID: secretID, VersionID: toVersionID, RotationID: r.ID,
		Detail: fmt.Sprintf("min_acks=%d consumers=%d", minAcks, len(snapshot)),
	})
	if err != nil {
		return nil, err
	}
	return cloneRotation(r), nil
}

// AckOutcome 是确认操作的结果。
type AckOutcome struct {
	// Applied 为 false 表示这是一次幂等重放，状态没有变化。
	Applied bool
	// Activated 表示本次确认触发了新版本激活。
	Activated bool
	Rotation  Rotation
}

// Acknowledge 记录消费者对轮换的确认。确认按 (轮换, 消费者) 幂等：
//   - 相同请求号 + 相同内容：幂等成功，不推进状态；
//   - 相同请求号 + 不同内容：返回 KindConflict；
//   - 同一消费者换请求号重复确认：返回 KindDuplicate；
//   - 非快照成员：返回 KindNotMember；
//   - 轮换已进入终态（迟到确认）：返回分类错误，不推进状态。
func (s *Service) Acknowledge(ctx context.Context, rotationID, consumerID, requestID string, payload []byte) (*AckOutcome, error) {
	const op = "Acknowledge"
	if rotationID == "" || consumerID == "" || requestID == "" {
		return nil, newError(KindInvalidInput, op, "rotation id, consumer id and request id are required")
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)

	r, ok := s.state.Rotations[rotationID]
	if !ok {
		return nil, newError(KindNotFound, op, "rotation not found")
	}

	// 幂等检查优先于状态检查：已记录的确认在轮换关闭后重放仍然成功。
	if prev, dup := r.Acks[consumerID]; dup {
		switch {
		case prev.RequestID == requestID && prev.PayloadHash == hash:
			return &AckOutcome{Applied: false, Rotation: *cloneRotation(r)}, nil
		case prev.RequestID == requestID:
			return nil, newError(KindConflict, op, "same request id with different payload")
		default:
			return nil, newError(KindDuplicate, op, "consumer already acknowledged with another request id")
		}
	}

	switch r.State {
	case RotationCollecting:
		// 继续处理
	case RotationTimedOut:
		return nil, newError(KindExpired, op, "rotation has timed out")
	default:
		return nil, newError(KindInvalidState, op, "rotation is already closed")
	}

	if !r.Consumers[consumerID] {
		return nil, newError(KindNotMember, op, "consumer is not in the frozen snapshot")
	}

	r.Acks[consumerID] = AckRecord{
		ConsumerID:  consumerID,
		RequestID:   requestID,
		PayloadHash: hash,
		At:          now,
	}
	events := []AuditEvent{{
		ID: newID("evt"), At: now, Type: AuditRotationAcked,
		SecretID: r.SecretID, VersionID: r.ToVersion, RotationID: r.ID,
		Actor: consumerID,
	}}

	activated := false
	if len(r.Acks) >= r.MinAcks {
		events = append(events, s.activateLocked(r, now)...)
		activated = true
	}
	if err := s.persistLocked(events...); err != nil {
		return nil, err
	}
	return &AckOutcome{Applied: true, Activated: activated, Rotation: *cloneRotation(r)}, nil
}

// CancelRotation 取消进行中的轮换，待激活版本随之作废。
// 已进入终态的轮换返回 KindInvalidState——激活成功后迟到的取消不会回退版本。
func (s *Service) CancelRotation(ctx context.Context, rotationID, actor string) error {
	const op = "CancelRotation"
	if rotationID == "" {
		return newError(KindInvalidInput, op, "rotation id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)

	r, ok := s.state.Rotations[rotationID]
	if !ok {
		return newError(KindNotFound, op, "rotation not found")
	}
	if r.State != RotationCollecting {
		return newError(KindInvalidState, op, "rotation is already closed")
	}

	r.State = RotationCancelled
	r.ClosedAt = now
	events := []AuditEvent{{
		ID: newID("evt"), At: now, Type: AuditRotationCancelled,
		SecretID: r.SecretID, VersionID: r.ToVersion, RotationID: r.ID,
		Actor: actor,
	}}
	if to, ok := s.state.Versions[r.ToVersion]; ok && to.State == VersionPending {
		to.State = VersionCancelled
	}
	return s.persistLocked(events...)
}

// Read 是受控读取：只有 active 或宽限期内的 grace 版本可读，
// 每次读取都会写审计。返回的明文由调用方负责清零。
func (s *Service) Read(ctx context.Context, secretID, versionID, requester, reason string) ([]byte, error) {
	const op = "Read"
	if secretID == "" || versionID == "" {
		return nil, newError(KindInvalidInput, op, "secret id and version id are required")
	}
	if requester == "" {
		return nil, newError(KindInvalidInput, op, "requester is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)

	v, ok := s.state.Versions[versionID]
	if !ok || v.SecretID != secretID {
		return nil, newError(KindNotFound, op, "version not found")
	}
	switch v.State {
	case VersionActive, VersionGrace:
		// 可读
	case VersionExpired:
		return nil, newError(KindExpired, op, "version has expired")
	default:
		return nil, newError(KindInvalidState, op, "version is not readable in state "+string(v.State))
	}

	plain, err := s.enc.decrypt(v.Ciphertext)
	if err != nil {
		return nil, err
	}
	err = s.persistLocked(AuditEvent{
		ID: newID("evt"), At: now, Type: AuditSecretRead,
		SecretID: secretID, VersionID: versionID,
		Actor: requester, Detail: reason,
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// VersionInfo 是版本的对外视图，不含密文。
type VersionInfo struct {
	ID          string
	State       VersionState
	CreatedAt   time.Time
	ActivatedAt time.Time
	GraceUntil  time.Time
}

// RotationInfo 是轮换的对外视图。
type RotationInfo struct {
	ID          string
	FromVersion string
	ToVersion   string
	State       RotationState
	MinAcks     int
	AckCount    int
	Consumers   []string
	Deadline    time.Time
}

// SecretStatus 是一个密钥的整体状态。
type SecretStatus struct {
	SecretID      string
	ActiveVersion string
	Versions      []VersionInfo
	Rotations     []RotationInfo
}

// Status 返回密钥的状态视图，不包含任何密文或明文。
func (s *Service) Status(ctx context.Context, secretID string) (*SecretStatus, error) {
	const op = "Status"
	if secretID == "" {
		return nil, newError(KindInvalidInput, op, "secret id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.expireLocked(now) {
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	}

	st := &SecretStatus{SecretID: secretID}
	for _, v := range s.state.Versions {
		if v.SecretID != secretID {
			continue
		}
		if v.State == VersionActive {
			st.ActiveVersion = v.ID
		}
		st.Versions = append(st.Versions, VersionInfo{
			ID: v.ID, State: v.State, CreatedAt: v.CreatedAt,
			ActivatedAt: v.ActivatedAt, GraceUntil: v.GraceUntil,
		})
	}
	for _, r := range s.state.Rotations {
		if r.SecretID != secretID {
			continue
		}
		consumers := make([]string, 0, len(r.Consumers))
		for c := range r.Consumers {
			consumers = append(consumers, c)
		}
		sort.Strings(consumers)
		st.Rotations = append(st.Rotations, RotationInfo{
			ID: r.ID, FromVersion: r.FromVersion, ToVersion: r.ToVersion,
			State: r.State, MinAcks: r.MinAcks, AckCount: len(r.Acks),
			Consumers: consumers, Deadline: r.Deadline,
		})
	}
	sort.Slice(st.Versions, func(i, j int) bool { return st.Versions[i].CreatedAt.Before(st.Versions[j].CreatedAt) })
	sort.Slice(st.Rotations, func(i, j int) bool { return st.Rotations[i].Deadline.Before(st.Rotations[j].Deadline) })
	return st, nil
}

// Sweep 推进所有超时与宽限期到期的状态迁移。后台应定期调用；
// 各操作入口也会惰性执行同样的逻辑，因此不调用 Sweep 也不会读到过期数据。
func (s *Service) Sweep(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expireLocked(s.now()) {
		return s.persistLocked()
	}
	return nil
}

// activateLocked 在锁内原子完成激活：轮换进入终态、新版本生效、旧版本进入宽限期。
func (s *Service) activateLocked(r *Rotation, now time.Time) []AuditEvent {
	r.State = RotationActivated
	r.ClosedAt = now

	events := []AuditEvent{{
		ID: newID("evt"), At: now, Type: AuditRotationActivated,
		SecretID: r.SecretID, VersionID: r.ToVersion, RotationID: r.ID,
	}}
	if to, ok := s.state.Versions[r.ToVersion]; ok {
		to.State = VersionActive
		to.ActivatedAt = now
	}
	if r.FromVersion != "" {
		if from, ok := s.state.Versions[r.FromVersion]; ok && from.State == VersionActive {
			from.State = VersionGrace
			from.GraceUntil = now.Add(r.GracePeriod)
			events = append(events, AuditEvent{
				ID: newID("evt"), At: now, Type: AuditVersionGrace,
				SecretID: r.SecretID, VersionID: from.ID, RotationID: r.ID,
				Detail: "grace_until=" + from.GraceUntil.Format(time.RFC3339Nano),
			})
		}
	}
	return events
}

// expireLocked 处理到期的轮换与宽限期，返回是否有状态变化。必须在锁内调用。
func (s *Service) expireLocked(now time.Time) bool {
	changed := false
	var events []AuditEvent
	for _, r := range s.state.Rotations {
		if r.State == RotationCollecting && !now.Before(r.Deadline) {
			r.State = RotationTimedOut
			r.ClosedAt = now
			changed = true
			events = append(events, AuditEvent{
				ID: newID("evt"), At: now, Type: AuditRotationTimedOut,
				SecretID: r.SecretID, VersionID: r.ToVersion, RotationID: r.ID,
			})
			if to, ok := s.state.Versions[r.ToVersion]; ok && to.State == VersionPending {
				to.State = VersionCancelled
			}
		}
	}
	for _, v := range s.state.Versions {
		if v.State == VersionGrace && !now.Before(v.GraceUntil) {
			v.State = VersionExpired
			changed = true
			events = append(events, AuditEvent{
				ID: newID("evt"), At: now, Type: AuditVersionExpired,
				SecretID: v.SecretID, VersionID: v.ID,
			})
		}
	}
	if changed {
		// 失败时仅丢失审计，状态仍会在下一次成功持久化时落盘。
		_ = s.store.AppendAudit(events...)
	}
	return changed
}

// persistLocked 保存状态并追加审计。必须在锁内调用。
func (s *Service) persistLocked(events ...AuditEvent) error {
	if err := s.store.Save(s.state); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	if err := s.store.AppendAudit(events...); err != nil {
		return fmt.Errorf("persist audit: %w", err)
	}
	return nil
}

func cloneVersion(v *Version) *Version {
	cp := *v
	cp.Ciphertext = append([]byte(nil), v.Ciphertext...)
	return &cp
}

func cloneRotation(r *Rotation) *Rotation {
	cp := *r
	cp.Consumers = make(map[string]bool, len(r.Consumers))
	for k, v := range r.Consumers {
		cp.Consumers[k] = v
	}
	cp.Acks = make(map[string]AckRecord, len(r.Acks))
	for k, v := range r.Acks {
		cp.Acks[k] = v
	}
	return &cp
}
