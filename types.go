package secretrotation

import "time"

// VersionStatus 描述单个密钥版本所处的阶段。
type VersionStatus string

const (
	// VersionPending 版本已创建并随轮换成为“待激活”版本，尚无任何读取者使用。
	VersionPending VersionStatus = "pending"
	// VersionActive 当前唯一可用于受控读取的版本。
	VersionActive VersionStatus = "active"
	// VersionGrace 已被新版本取代的旧版本，处于只读宽限期，到期后读取必须失败。
	VersionGrace VersionStatus = "grace"
	// VersionRetired 宽限期结束，版本彻底失效。
	VersionRetired VersionStatus = "retired"
	// VersionRevoked 版本因疑似泄露被紧急撤销，永久失效：任何读取都被拒绝，
	// 且不存在任何路径能让该版本再次激活。
	VersionRevoked VersionStatus = "revoked"
)

// RotationStatus 描述一次轮换流程的状态机。
type RotationStatus string

const (
	// RotationPending 轮换已发起，新版本待激活，正在收集快照成员的确认。
	RotationPending RotationStatus = "pending"
	// RotationActivated 新版本已原子激活，轮换成功结束（终态）。
	RotationActivated RotationStatus = "activated"
	// RotationCancelled 轮换被显式取消，待激活版本随之废弃（终态）。
	RotationCancelled RotationStatus = "cancelled"
	// RotationTimedOut 轮换在截止时间前未满足激活条件，由超时处理终结（终态）。
	RotationTimedOut RotationStatus = "timed_out"
)

// isTerminal 判断轮换状态是否为终态。激活、取消、超时互为竞争者，
// 任何时刻只允许一个终态落库。
func (s RotationStatus) isTerminal() bool {
	return s == RotationActivated || s == RotationCancelled || s == RotationTimedOut
}

// Policy 定义发起轮换时冻结的确认策略。
type Policy struct {
	// RequiredConsumers 为本次轮换必须确认“已加载新版本”的消费者集合快照。
	// 发起时复制一份冻结，后续成员增删不改变门槛；为空表示无需任何确认，
	// 可在发起后立即激活。
	RequiredConsumers []string
	// Timeout 轮换发起后的最长等待时间。<=0 表示不设超时，
	// 此时只能通过取消终结未完成的轮换。
	Timeout time.Duration
}

// CreateKeyInput 创建密钥的输入。Plaintext 只会进入受控加密通道，
// 不会出现在持久化明文、日志或错误消息中。
type CreateKeyInput struct {
	Name      string
	Plaintext []byte
	// GracePeriod 旧版本被替换后允许旧读取者继续工作的宽限期，必须 >= 0。
	GracePeriod time.Duration
	// Readers 允许受控读取该密钥的消费者白名单；nil 表示不限制。
	Readers []string
}

// StartRotationInput 发起一次轮换。
type StartRotationInput struct {
	KeyName string
	// NewPlaintext 新版本明文，仅经加密器处理。
	NewPlaintext []byte
	Policy       Policy
	// RequestID 用于发起动作自身的幂等去重（同一密钥下相同 RequestID
	// 必须指向同一次轮换）。
	RequestID string
}

// AcknowledgeInput 消费者确认已加载待激活版本。
type AcknowledgeInput struct {
	KeyName       string
	RotationID    string
	Consumer      string
	LoadedVersion int
	RequestID     string
}

// RevokeInput 紧急撤销一个疑似泄露的版本。
type RevokeInput struct {
	KeyName string
	// Version 为要撤销的版本号，必须 > 0（不允许隐式撤销“当前版本”，
	// 以避免在调用方状态过期时误伤其它版本）。
	Version int
	// Actor 为执行撤销的操作者/系统标识，仅进入审计记录。
	Actor string
	// Reason 为撤销原因，仅允许承载非敏感元数据，不得包含密钥明文。
	Reason string
	// FallbackToSafe 为 true 时，若撤销的是当前 active 版本，尝试让最近一个
	// 仍处于 grace 宽限期且尚未到期的历史版本临时接替；找不到合适版本则
	// fail-closed（active 置空，此后读取明确失败，绝不悄悄切换到任意旧值）。
	FallbackToSafe bool
	// RequestID 用于撤销动作的幂等去重：同一密钥下相同 RequestID 必须指向
	// 同一次撤销。
	RequestID string
}

// RevocationInfo 撤销动作完成后的非敏感结果。
type RevocationInfo struct {
	KeyName string
	// RevokedVersion 被永久撤销的版本号。
	RevokedVersion int
	// RevokedAt 撤销生效时刻。
	RevokedAt time.Time
	// FallbackVersion 临时接替的安全历史版本号；0 表示没有接替版本
	//（密钥进入 fail-closed，读取明确失败）。
	FallbackVersion int
	// AlreadyRevoked 为 true 表示本次调用是重复撤销的幂等返回，状态未被
	// 再次改写。
	AlreadyRevoked bool
}

// SecretView 是受控读取返回的敏感载荷。
type SecretView struct {
	KeyName       string
	Version       int
	Plaintext     []byte
	VersionStatus VersionStatus
}

// VersionInfo 状态查询用的版本元数据（不含任何密钥材料）。
type VersionInfo struct {
	Number      int
	Status      VersionStatus
	CreatedAt   time.Time
	ActivatedAt time.Time
	// RetireAt 仅当状态为 grace 时有意义，表示宽限期结束时刻。
	RetireAt time.Time
	// RevokedAt 仅当状态为 revoked 时有意义，表示紧急撤销生效时刻。
	RevokedAt time.Time
}

// RotationInfo 状态查询用的轮换元数据。
type RotationInfo struct {
	ID                string
	Status            RotationStatus
	PendingVersion    int
	RequiredConsumers []string
	Acks              []string
	CreatedAt         time.Time
	Deadline          time.Time
	ActivatedAt       time.Time
	EndedAt           time.Time
}

// KeyState 是持久化与内存状态共享的密钥聚合根快照。
type KeyState struct {
	Name        string
	GracePeriod time.Duration
	Readers     []string
	Versions    []*versionState
	Rotations   []*rotationState
	// ActiveVersion 为 0 表示尚无激活版本；撤销当前版本且无安全替代时，
	// 该字段同样回到 0，表示密钥 fail-closed——读取必须明确失败，
	// 服务不得自行切换到任何其它版本。
	ActiveVersion int
	// PendingRotation 非空表示当前存在未终结的轮换。
	PendingRotation string
	// KeyRequests 记录密钥级动作幂等键：发起轮换/撤销的 RequestID -> 动作描述。
	KeyRequests map[string]string
	// RevokeRequests 记录撤销动作幂等键：RequestID -> 被撤销的版本号。
	RevokeRequests map[string]int
	// Revocations 为该密钥全部撤销记录，与状态变更在同一次 CAS 内原子保存。
	Revocations []*revocationState
	// Revision 是存储层的乐观锁版本号，服务层不解释其含义。
	Revision int64
}

// versionState 是版本的内部持久化形态。ciphertext 为静态加密后的密文，
// 任何日志/错误都不得打印该字段。
type versionState struct {
	Number      int
	Status      VersionStatus
	Ciphertext  []byte
	CreatedAt   time.Time
	ActivatedAt time.Time
	RetireAt    time.Time
	// RevokedAt 仅当状态为 revoked 时有意义，记录撤销生效时刻。
	RevokedAt time.Time
}

// rotationState 是轮换的内部持久化形态。
type rotationState struct {
	ID             string
	Status         RotationStatus
	PendingVersion int
	// Required 为冻结的消费者快照。
	Required []string
	// Acks 已确认消费者；ackRequests 记录每个消费者首次确认使用的请求号。
	Acks        []string
	AckRequests map[string]string
	CreatedAt   time.Time
	Deadline    time.Time
	ActivatedAt time.Time
	EndedAt     time.Time
	// Requests 记录本次轮换生命周期内出现过的请求号（发起、取消），
	// 用于动作级幂等。
	Requests map[string]string
}

// revocationState 是一次紧急撤销的内部持久化形态，只承载非敏感元数据，
// 绝不包含密钥明文或密文。
type revocationState struct {
	// RevokedVersion 被永久撤销的版本号。
	RevokedVersion int
	// FallbackVersion 临时接替的安全历史版本号；0 表示无替代（fail-closed）。
	FallbackVersion int
	Actor           string
	Reason          string
	RevokedAt       time.Time
}

// RevocationRecord 是状态查询用的一条撤销记录（不含任何密钥材料）。
type RevocationRecord struct {
	// RevokedVersion 被永久撤销的版本号。
	RevokedVersion int
	// FallbackVersion 当时临时接替的安全历史版本号；0 表示无替代（fail-closed）。
	FallbackVersion int
	Actor           string
	Reason          string
	RevokedAt       time.Time
}

// AuditEvent 描述一条与密钥/轮换相关的审计记录。
type AuditEvent struct {
	Time       time.Time
	KeyName    string
	RotationID string
	Version    int
	Action     string
	Actor      string
	// Detail 只允许承载非敏感元数据。
	Detail string
}
