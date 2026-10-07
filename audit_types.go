package secretrotation

import "time"

// AuditStatus 描述一次轮换审计所处的阶段。
type AuditStatus string

const (
	// AuditOpen 审计已发起，正在收集截止前各服务实例的版本回报。
	AuditOpen AuditStatus = "open"
	// AuditClosed 审计已在截止之后结案；结论不可变，之后发现的旧版本
	// 实例只能产生新的问题记录。
	AuditClosed AuditStatus = "closed"
)

// StartAuditInput 发起一次轮换审计。发起时固定秘密标识、服务清单、
// 当前安全版本与截止时刻；这些参数在审计生命周期内不可变。
type StartAuditInput struct {
	KeyName  string
	AuditID  string
	Services []string
	// Deadline 为绝对截止时刻；必须晚于审计发起时刻。
	Deadline  time.Time
	RequestID string
}

// ReportInstanceInput 上报某个服务实例当前实际运行的版本。
// 同一实例重复回报以“截止前最新一次”为准，重部署产生的新实例可用
// Replaces 声明它取代了哪个旧实例。
type ReportInstanceInput struct {
	KeyName   string
	AuditID   string
	Service   string
	Instance  string
	Version   int
	Replaces  string
	RequestID string
}

// CloseAuditInput 在截止时间之后结案。结案快照只代表当时结果。
type CloseAuditInput struct {
	KeyName   string
	AuditID   string
	RequestID string
}

// InstanceAuditView 是审计视角下的单个实例状态（不含任何密钥材料）。
type InstanceAuditView struct {
	Service    string
	Instance   string
	Version    int
	ReportedAt time.Time
	Replaces   string
	// Complete 表示该实例截止前最近一次回报的版本即审计认定的安全版本。
	Complete bool
	// BeforeDeadline 表示该回报是否在截止前收到；截止后的回报不能计入达标。
	BeforeDeadline bool
}

// ServiceAuditView 按服务聚合的审计视图。
type ServiceAuditView struct {
	Name string
	// CurrentSafeVersion 为审计认定的当前安全版本。
	CurrentSafeVersion int
	// RevokedVersions 为已被撤销/退役的版本号列表。
	RevokedVersions []int
	// Complete 为截止前已回报安全版本的实例。
	Complete []InstanceAuditView
	// Incomplete 为仍未达标的实例：从未回报、回报旧版本，
	// 或回报在截止之后才到达。
	Incomplete []InstanceAuditView
	// LastReport 为该服务最近一次收到的回报。
	LastReport *InstanceAuditView
}

// AuditIssueView 是结案后追加问题记录的非敏感视图。
type AuditIssueView struct {
	ID       string
	Service  string
	Instance string
	Version  int
	FoundAt  time.Time
}

// AuditInfo 是审计的非敏感视图：秘密只以名称（标识）出现，
// 不包含明文或密文。
type AuditInfo struct {
	KeyName           string
	AuditID           string
	Status            AuditStatus
	SafeVersion       int
	Services          []string
	Deadline          time.Time
	CreatedAt         time.Time
	ClosedAt          time.Time
	ClosedSafeVersion int
	// RevokedVersions 为审计目标密钥当前已撤销/退役的版本号。
	RevokedVersions []int
	Instances       []InstanceAuditView
	ServicesView    []ServiceAuditView
	Issues          []AuditIssueView
}
