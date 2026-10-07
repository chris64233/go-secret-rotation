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
	// Audits 为针对该密钥发起的轮换审计。审计记录只承载秘密标识、
	// 版本号、服务/实例等元数据，严禁保存任何明文或密文材料。
	Audits []*auditState
	// ActiveVersion 为 0 表示尚无激活版本。
	ActiveVersion int
	// PendingRotation 非空表示当前存在未终结的轮换。
	PendingRotation string
	// KeyRequests 记录密钥级动作幂等键：发起轮换 RequestID -> 轮换 ID。
	KeyRequests map[string]string
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

// auditState 是轮换审计的内部持久化形态。审计在发起时冻结秘密标识、
// 必须达标的服务清单、安全版本与截止时刻；结案后结果不可变，结案之后
// 发现的旧版本实例只能追加 issueRecords，绝不回写结案结论。
type auditState struct {
	// AuditID 为审计号，同一密钥下唯一；跨密钥的唯一性由服务层索引保证。
	AuditID string
	Status  AuditStatus
	// SafeVersion 为发起时固定的“当前安全版本”。结案时若当前 active
	// 已不是该版本，审计不能提前结案。
	SafeVersion int
	// Services 为发起时冻结的服务清单快照。
	Services []string
	// Deadline 为发起时固定的截止时刻；截止后才允许结案。
	Deadline  time.Time
	CreatedAt time.Time
	// ClosedAt/ClosedSafeVersion 为结案时刻与结案时认定的安全版本；
	// 未结案时为零值。
	ClosedAt          time.Time
	ClosedSafeVersion int
	// Instances 记录每个实例截止前的最新有效回报；completed 等结论
	// 一律在读取/结案时按回报实际版本现算，不沿用任何持久化的
	// “已完成”标记，避免重部署后沿用过时结论。
	Instances map[string]*auditInstanceState
	// Issues 为结案之后发现旧版本实例时追加的问题记录，只增不改。
	Issues []*auditIssue
	// StartRequest 记录发起该审计的请求号，用于请求级幂等/冲突。
	StartRequest string
	// CloseRequest 记录结案动作使用的请求号。
	CloseRequest string
	// ReportRequests 记录回报请求号 -> 回报内容指纹。
	ReportRequests map[string]string
}

// auditInstanceState 是单个实例在审计窗口内的最新回报快照。
type auditInstanceState struct {
	Service    string
	Instance   string
	Version    int
	ReportedAt time.Time
	// Replaces 为该实例重部署时所取代的旧实例 ID；为空表示未声明。
	Replaces string
}

// auditIssue 是审计结案之后追加的问题记录。
type auditIssue struct {
	ID       string
	Service  string
	Instance string
	Version  int
	FoundAt  time.Time
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
