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
	// ActiveVersion 为 0 表示尚无激活版本。
	ActiveVersion int
	// PendingRotation 非空表示当前存在未终结的轮换。
	PendingRotation string
	// KeyRequests 记录密钥级动作幂等键：发起轮换 RequestID -> 轮换 ID。
	KeyRequests map[string]string
	// AuditRequests 记录审计级动作幂等键：RequestID -> "auditID:action"。
	AuditRequests map[string]string
	// Instances 为跨审计的实例回报注册表：service -> instanceID -> 最近回报。
	// 审计发起时据此冻结实例快照；注册表不保存任何密钥材料。
	Instances map[string]map[string]*instanceReportState
	// AuditReports 保存最近回报用于“按服务查看最近回报”：
	// service -> 有序（时间倒序）的回报条目，服务层裁剪长度。
	AuditReports map[string][]*instanceReportState
	// Audits 该密钥下的全部轮换审计。
	Audits []*auditState
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

// instanceReportState 是一条实例回报的内部持久化形态，只含元数据。
type instanceReportState struct {
	Service          string
	InstanceID       string
	DeployGeneration int64
	Version          int
	ReportedAt       time.Time
	RequestID        string
}

// auditInstanceState 是审计冻结视角下的单个实例结论。
type auditInstanceState struct {
	Service        string
	InstanceID     string
	InSnapshot     bool
	LastGeneration int64
	LastVersion    int
	LastReportAt   time.Time
	LastReportLate bool
	// CompleteWhenClosed 在结案时刻冻结；未结案时为 false。
	CompleteWhenClosed bool
}

// auditIssueState 是结案后追加问题记录的内部形态。
type auditIssueState struct {
	ID               string
	DiscoveredAt     time.Time
	Service          string
	InstanceID       string
	DeployGeneration int64
	Version          int
	Detail           string
}

// auditState 是一次轮换审计的内部持久化形态。其中只保存秘密标识
// （密钥名）、版本号、服务与实例标识等元数据，绝不保存秘密明文或密文。
type auditState struct {
	ID              string
	Status          AuditStatus
	Services        []string
	SafeVersion     int
	RevokedVersions []int
	StartedAt       time.Time
	Deadline        time.Time
	ClosedAt        time.Time
	FullyComplete   bool
	// Instances 为审计观测的实例集合：service|instanceID -> 实例结论。
	// 发起时从注册表冻结快照实例（InSnapshot=true）；之后新出现的实例
	// 以 InSnapshot=false 进入，永不计入已完成。
	Instances map[string]*auditInstanceState
	// Issues 结案后追加的问题记录，结案结论本身不被修改。
	Issues []*auditIssueState
	// Requests 记录本审计生命周期内出现过的请求号与动作。
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

// --- 轮换审计（紧急撤销/回退后的版本达标核查） -------------------------------

// AuditStatus 描述一次轮换审计是否已经结案。
type AuditStatus string

const (
	// AuditOpen 审计进行中：可继续接收服务回报、查询进度。
	AuditOpen AuditStatus = "open"
	// AuditClosed 审计已结案：结论冻结，之后任何发现都不得改写历史。
	AuditClosed AuditStatus = "closed"
)

// ReportInstanceInput 是某个服务实例回报自身当前持有的秘密版本。
// 回报只承载元数据（版本号等），绝不承载任何秘密材料。
type ReportInstanceInput struct {
	// KeyName 秘密标识（密钥名），回报必须针对一个已存在的秘密。
	KeyName string
	// Service 回报所属服务，必须在审计冻结的服务清单内才会计入该审计。
	Service string
	// InstanceID 实例的稳定标识（如实例主机名/Pod UID）。
	InstanceID string
	// DeployGeneration 单调递增的部署代号：实例重新部署后该值必须变大，
	// 服务层据此识别“重部署竞态”，拒绝旧部署的迟到回报覆盖新部署。
	DeployGeneration int64
	// Version 该实例当前实际使用的秘密版本号。
	Version int
	// RequestID 回报动作的幂等键：相同请求号返回同一结果；
	// 被不同内容复用返回 CodeConflict。
	RequestID string
}

// CreateAuditInput 发起一次轮换审计。审计发起时固定秘密标识、服务清单、
// 当前安全版本、被撤销版本集合与实例快照；这些都不会随之后的变化而改变。
type CreateAuditInput struct {
	// KeyName 被审计秘密的固定标识。
	KeyName string
	// AuditID 由调用方分配的审计号（相同审计号重复请求返回原结果）。
	AuditID string
	// Services 本次审计冻结的服务清单；审计期间服务集合不可变。
	Services []string
	// Deadline 回报截止时间：截止之后到达的回报标记为逾期，
	// 不能再把实例计入“已完成”。
	Deadline time.Time
	// RequestID 发起动作自身的幂等键。
	RequestID string
}

// CloseAuditInput 对一次审计结案。结案结论只代表结案当时的状态。
type CloseAuditInput struct {
	KeyName   string
	AuditID   string
	RequestID string
}

// InstanceAuditInfo 是审计视角下单个实例的达标结论（不含密钥材料）。
type InstanceAuditInfo struct {
	Service    string
	InstanceID string
	// InSnapshot 为 false 表示该实例在审计开始之后才首次出现，
	// 永远不能被算作“已完成”。
	InSnapshot bool
	// LastGeneration / LastVersion / LastReportAt 为该实例截至结案
	// （或查询当时）最新部署的最近一次回报。
	LastGeneration int64
	LastVersion    int
	LastReportAt   time.Time
	// Late 为 true 表示最近一次回报到达时已超过截止时间。
	Late bool
	// Complete 表示该实例是否已换到安全版本：
	// 快照实例、截止前、当前部署回报版本恰好等于安全版本时才为 true。
	Complete bool
}

// ServiceAuditInfo 是审计结论中单个服务的汇总。
type ServiceAuditInfo struct {
	Name string
	// SafeVersion 审计发起时固定的当前安全版本；只有回报该版本才能计入。
	SafeVersion int
	// RevokedVersions 审计发起时固定的被撤销版本集合（不含安全版本）。
	RevokedVersions []int
	// Complete 已换到安全版本的快照实例。
	Complete []InstanceAuditInfo
	// Incomplete 仍未达标的实例：仍在使用被撤销版本、重部署后回报逾期、
	// 以及审计开始后才新出现的实例（InSnapshot=false）。
	Incomplete []InstanceAuditInfo
}

// AuditIssue 是审计结案之后才发现旧版本实例时产生的“问题记录”。
// 它是追加式的：绝不改写或撤回已经冻结的结案结论。
type AuditIssue struct {
	ID               string
	DiscoveredAt     time.Time
	Service          string
	InstanceID       string
	DeployGeneration int64
	Version          int
	Detail           string
}

// AuditInfo 是一次轮换审计的非敏感视图，审计记录中不含任何秘密明文或密文。
type AuditInfo struct {
	AuditID         string
	KeyName         string
	Status          AuditStatus
	Services        []string
	SafeVersion     int
	RevokedVersions []int
	StartedAt       time.Time
	Deadline        time.Time
	ClosedAt        time.Time
	// FullyComplete 仅在结案时有意义：所有服务的全部快照实例均达标。
	FullyComplete bool
	// ServiceResults 按服务名排序的逐服务结论。
	ServiceResults []ServiceAuditInfo
	// Issues 结案后追加发现的问题（仅查询视图动态带出，不回写结案）。
	Issues []AuditIssue
}

// ServiceAuditView 是“按服务查看最近回报和仍未达标实例”的查询视图。
type ServiceAuditView struct {
	KeyName         string
	AuditID         string
	Service         string
	SafeVersion     int
	RevokedVersions []int
	// RecentReports 该服务最近的实例回报（新的在前）。
	RecentReports []InstanceAuditInfo
	// Outstanding 仍未达标的实例（含审计开始后新出现的实例）。
	Outstanding []InstanceAuditInfo
}
