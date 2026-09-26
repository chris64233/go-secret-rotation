package secretrotation

import (
	"errors"
	"fmt"
)

// Code 是与传输无关的错误分类码，调用方应按 Code 而不是错误文本做判断。
type Code string

const (
	// CodeInvalidArgument 请求参数不合法。
	CodeInvalidArgument Code = "invalid_argument"
	// CodeNotFound 指定的密钥、版本或轮换不存在。
	CodeNotFound Code = "not_found"
	// CodeAlreadyExists 同名密钥或已有进行中的轮换。
	CodeAlreadyExists Code = "already_exists"
	// CodeConflict 幂等冲突，例如同一消费者+轮换已用不同请求内容提交过。
	CodeConflict Code = "conflict"
	// CodeFailedPrecondition 当前状态不允许该操作，例如未达到确认门槛就激活、对终态轮换迟到取消。
	CodeFailedPrecondition Code = "failed_precondition"
	// CodePermissionDenied 消费者不在轮换快照或无权读取该密钥。
	CodePermissionDenied Code = "permission_denied"
	// CodeExpired 版本宽限期已结束或轮换已超时。
	CodeExpired Code = "expired"
	// CodeInternal 服务内部错误（持久化、加解密失败等），错误详情不会包含密钥明文。
	CodeInternal Code = "internal"
)

// Error 是本包所有错误的统一类型。错误信息中只允许出现密钥名、版本号、
// 消费者标识等元数据，严禁携带密钥明文或密文片段。
type Error struct {
	Code Code
	Op   string
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("secretrotation %s: %s: %v", e.Op, e.Msg, e.Err)
	}
	return fmt.Sprintf("secretrotation %s: %s", e.Op, e.Msg)
}

func (e *Error) Unwrap() error { return e.Err }

func newError(code Code, op, msg string) *Error {
	return &Error{Code: code, Op: op, Msg: msg}
}

// ErrorCode 返回 err 中的分类码；非本包错误返回 CodeInternal。
func ErrorCode(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}
