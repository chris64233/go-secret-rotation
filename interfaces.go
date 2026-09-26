package secretrotation

import "context"

// Encryptor 负责密钥明文的静态加密。实现方必须使用 AEAD 等带完整性校验的
// 方案；本服务保证明文只以参数形式进入 Encrypt、以返回值形式离开 Decrypt，
// 不会写入日志、错误消息或审计记录。
type Encryptor interface {
	Encrypt(ctx context.Context, keyName string, version int, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, keyName string, version int, ciphertext []byte) (plaintext []byte, err error)
}

// Store 是 KeyState 的持久化接口。实现必须在单个 CompareAndSwap 内完成
// 原子的条件更新：expected 为调用方读取到的状态，若并发下已被他人修改，
// 必须返回 ErrCASConflict 让服务层重试。
type Store interface {
	// Get 读取密钥当前状态；不存在返回 ErrNotFound。
	Get(ctx context.Context, name string) (*KeyState, error)
	// CompareAndSwap 条件写入。expected==nil 表示新建；
	// 状态已被并发修改时返回 ErrCASConflict。
	CompareAndSwap(ctx context.Context, expected, next *KeyState) error
	// ListKeys 枚举全部密钥名，供超时扫描使用。
	ListKeys(ctx context.Context) ([]string, error)
}

// AuditSink 接收审计事件。实现方不得因审计失败改变主流程结果之外的语义；
// 事件中不含密钥明文。
type AuditSink interface {
	Write(ctx context.Context, event AuditEvent) error
}

// 存储层哨兵错误，服务层据此分类。
var (
	// ErrNotFound 由 Store.Get 在密钥不存在时返回。
	ErrNotFound = storableError("secretrotation: key not found")
	// ErrCASConflict 由 Store.CompareAndSwap 在条件不匹配时返回。
	ErrCASConflict = storableError("secretrotation: concurrent modification")
)

type storableError string

func (e storableError) Error() string { return string(e) }
