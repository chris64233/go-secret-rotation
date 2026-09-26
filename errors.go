package secretrotation

import "errors"

// Kind 对错误进行分类，调用方可以据此做重试、告警或映射为传输层状态码。
// 错误消息中只允许出现 ID、状态等元信息，绝不包含密钥明文。
type Kind string

const (
	// KindNotFound 表示引用的密钥、版本或轮换不存在。
	KindNotFound Kind = "not_found"
	// KindConflict 表示幂等冲突，例如同一请求号提交了不同内容。
	KindConflict Kind = "conflict"
	// KindInvalidState 表示当前状态不允许该操作，例如对已进入终态的轮换再次确认或取消。
	KindInvalidState Kind = "invalid_state"
	// KindExpired 表示轮换已超时或版本已过宽限期。
	KindExpired Kind = "expired"
	// KindNotMember 表示确认者不在轮换冻结的消费者快照中。
	KindNotMember Kind = "not_member"
	// KindDuplicate 表示消费者已用其他请求号确认过本次轮换。
	KindDuplicate Kind = "duplicate"
	// KindInvalidInput 表示请求参数不合法。
	KindInvalidInput Kind = "invalid_input"
)

// Error 是服务返回的分类错误。
type Error struct {
	Kind Kind
	Op   string
	Msg  string
}

func (e *Error) Error() string {
	return e.Op + ": " + string(e.Kind) + ": " + e.Msg
}

func newError(kind Kind, op, msg string) *Error {
	return &Error{Kind: kind, Op: op, Msg: msg}
}

// IsKind 判断 err 是否为指定分类的错误。
func IsKind(err error, kind Kind) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind == kind
	}
	return false
}
