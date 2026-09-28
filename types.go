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
	// VersionRevoked 版本因疑似泄露被紧急撤销：立即停止向任何新读取提供，
	// 且为终态，永远不能再次激活或被选为回退目标。
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
	// Version 要撤销的版本号，必须 > 0。
	Version int
	// Reason 为只含非敏感元数据的撤销原因，会进入审计与撤销记录，
	// 严禁写入密钥材料。
	Reason string
	// Actor 为执行撤销的主体，用于审计；可为空。
	Actor string
	// RequestID 用于撤销动作的幂等去重（同一密钥下相同 RequestID
	// 必须指向同一次撤销）。
	RequestID string
}

// SecretView 是受控读取返回的敏感载荷。
type SecretView struct {
	KeyName       string
	Version       int
	Plaintext     []byte
	VersionStatus VersionStatus
	// Fallback 为 true 表示当前版本已被撤销，本次返回的是撤销时选定的
	// 历史安全版本（临时接替），其一旦宽限期到期，读取将明确失败。
	Fallback bool
}

// VersionInfo 状态查询用的版本元数据（不含任何密钥材料）。
type VersionInfo struct {
	Number      int
	Status      VersionStatus
	CreatedAt   time.Time
	ActivatedAt time.Time
	// RetireAt 仅当状态为 grace 时有意义，表示宽限期结束时刻。
	RetireAt time.Time
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
	// ActiveVersion 为 0 表示尚无激活版本。
	ActiveVersion int
	// ServingVersion 是当前“读当前版本”实际服务的版本指针：
	// 正常情况下等于 ActiveVersion；当前 active 版本被撤销后，它可能临时
	// 指向撤销时选定的历史安全版本（处于 grace 宽限期内）。为 0 表示当前
	// 没有任何可服务版本，读当前版本必须明确失败，服务层不得自行切换到
	// 其他历史版本。
	ServingVersion int
	// PendingRotation 非空表示当前存在未终结的轮换。
	PendingRotation string
	// KeyRequests 记录密钥级动作幂等键：发起轮换 RequestID -> 轮换 ID。
	KeyRequests map[string]string
	// RevocationRequests 记录撤销动作幂等键：RequestID -> 撤销记录 ID。
	RevocationRequests map[string]string
	// Revocations 为该密钥全部紧急撤销记录（只含元数据）。
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
}

// revocationState 是紧急撤销的内部持久化形态（只含元数据，不含密钥材料）。
type revocationState struct {
	ID              string
	Version         int
	Reason          string
	Actor           string
	CreatedAt       time.Time
	FallbackVersion int
	// Requests 记录本次撤销使用过的请求号，用于动作级幂等。
	Requests map[string]string
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
