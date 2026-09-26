package secretrotation

import "time"

// VersionState 描述密钥版本的生命周期。
//
//	pending ──激活──> active ──被替换──> grace ──宽限期结束──> expired
//	pending ──轮换取消/超时──> cancelled
type VersionState string

const (
	VersionPending   VersionState = "pending"
	VersionActive    VersionState = "active"
	VersionGrace     VersionState = "grace"
	VersionExpired   VersionState = "expired"
	VersionCancelled VersionState = "cancelled"
)

// RotationState 描述轮换流程的状态。activated / cancelled / timed_out 均为终态，
// 一次轮换只能进入其中一个终态。
type RotationState string

const (
	RotationCollecting RotationState = "collecting"
	RotationActivated  RotationState = "activated"
	RotationCancelled  RotationState = "cancelled"
	RotationTimedOut   RotationState = "timed_out"
)

// Terminal 报告轮换是否已进入终态。
func (s RotationState) Terminal() bool {
	return s == RotationActivated || s == RotationCancelled || s == RotationTimedOut
}

// Version 是不可变的密钥版本。明文绝不落盘，只保存密文。
type Version struct {
	ID          string       `json:"id"`
	SecretID    string       `json:"secret_id"`
	State       VersionState `json:"state"`
	Ciphertext  []byte       `json:"ciphertext"`
	CreatedAt   time.Time    `json:"created_at"`
	ActivatedAt time.Time    `json:"activated_at,omitempty"`
	GraceUntil  time.Time    `json:"grace_until,omitempty"`
}

// AckRecord 记录一次消费者确认。同一 (轮换, 消费者) 只允许一条记录，
// 用于实现幂等与冲突检测。
type AckRecord struct {
	ConsumerID  string    `json:"consumer_id"`
	RequestID   string    `json:"request_id"`
	PayloadHash string    `json:"payload_hash"`
	At          time.Time `json:"at"`
}

// Rotation 是一次轮换流程。Consumers 为发起时冻结的消费者快照，
// 后续成员变化不会改变本次轮换的确认门槛。
type Rotation struct {
	ID          string               `json:"id"`
	SecretID    string               `json:"secret_id"`
	FromVersion string               `json:"from_version"` // 首次激活时为空
	ToVersion   string               `json:"to_version"`
	State       RotationState        `json:"state"`
	Consumers   map[string]bool      `json:"consumers"` // 冻结快照
	MinAcks     int                  `json:"min_acks"`
	Acks        map[string]AckRecord `json:"acks"`
	GracePeriod time.Duration        `json:"grace_period"`
	Deadline    time.Time            `json:"deadline"`
	CreatedAt   time.Time            `json:"created_at"`
	ClosedAt    time.Time            `json:"closed_at,omitempty"`
}

// RotationPolicy 是发起轮换时的配置。
type RotationPolicy struct {
	// MinAcks 为激活所需的最少确认数；0 表示需要快照内全部消费者确认。
	MinAcks int
	// AckTimeout 为确认收集的超时时长，超时后轮换进入 timed_out。
	AckTimeout time.Duration
	// GracePeriod 为新版本激活后旧版本的宽限期。
	GracePeriod time.Duration
}

// AuditEvent 是一条审计记录。Detail 只允许存放元信息，绝不包含明文。
type AuditEvent struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Type       string    `json:"type"`
	SecretID   string    `json:"secret_id,omitempty"`
	VersionID  string    `json:"version_id,omitempty"`
	RotationID string    `json:"rotation_id,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// 审计事件类型。
const (
	AuditVersionCreated    = "version.created"
	AuditRotationStarted   = "rotation.started"
	AuditRotationAcked     = "rotation.acknowledged"
	AuditRotationActivated = "rotation.activated"
	AuditRotationCancelled = "rotation.cancelled"
	AuditRotationTimedOut  = "rotation.timed_out"
	AuditVersionGrace      = "version.grace"
	AuditVersionExpired    = "version.expired"
	AuditSecretRead        = "secret.read"
)

// persistedState 是持久化的全部状态。
type persistedState struct {
	Versions  map[string]*Version  `json:"versions"`
	Rotations map[string]*Rotation `json:"rotations"`
}

func newPersistedState() *persistedState {
	return &persistedState{
		Versions:  make(map[string]*Version),
		Rotations: make(map[string]*Rotation),
	}
}
