# go-secret-rotation

用于承载应用密钥版本与消费者确认管理相关的 Go 服务代码。核心是一个需要多个消费者确认才能激活新版本的密钥轮换编排服务。

开发环境：Go 1.23.0。

## 设计要点

### 不可变版本与状态机

密钥按不可变版本管理，版本状态机：

```
pending ──激活──> active ──被替换──> grace ──宽限期结束──> expired
pending ──轮换取消/超时──> cancelled
```

轮换流程状态机（`activated` / `cancelled` / `timed_out` 均为终态）：

```
collecting ──达到确认门槛──> activated
collecting ──主动取消──> cancelled
collecting ──超过确认时限──> timed_out
```

### 冻结的消费者快照

发起轮换（`StartRotation`）时冻结本次必须确认的消费者集合与确认门槛（`MinAcks`，0 表示快照全员）。后续消费者成员变化不会暗中改变本次轮换的门槛——非快照成员的确认返回 `KindNotMember`，不推进状态。

### 幂等确认

确认按 **(轮换, 消费者)** 幂等：

| 情况 | 结果 |
| --- | --- |
| 相同请求号 + 相同内容 | 幂等成功（`Applied=false`），不推进状态 |
| 相同请求号 + 不同内容 | `KindConflict` |
| 同一消费者换请求号重复确认 | `KindDuplicate` |
| 非快照成员 | `KindNotMember` |
| 轮换已进入终态（迟到确认） | `KindInvalidState` / `KindExpired`，不推进状态 |

### 并发与终态唯一性

所有状态迁移在同一把互斥锁内完成：达到门槛时原子激活（新版本生效、旧版本同时进入宽限期），与取消、超时竞争时只会产生一个终态。激活成功后迟到的取消返回 `KindInvalidState`，不会回退版本。超时与宽限期到期由 `Sweep` 定期推进，各操作入口也会惰性执行同样的到期检查，因此不调用 `Sweep` 也不会读到过期数据。

### 明文保护

- 明文只在 `CreateVersion` 调用内短暂存在，落盘前用 AES-256-GCM 加密，持久化层只有密文；
- 明文只能通过受控读取 `Read`（要求 requester，写审计）返回；
- 审计事件、错误消息只包含 ID、状态等元信息，绝不包含明文；
- 宽限期结束后旧版本读取返回 `KindExpired`。

## API 概览

```go
svc, _ := secretrotation.NewService(store, masterKey32Bytes) // 从 store 恢复状态

v, _  := svc.CreateVersion(ctx, "db-password", plaintext)     // 创建 pending 版本
r, _  := svc.StartRotation(ctx, "db-password", v.ID,
        []string{"app-1", "app-2"},
        secretrotation.RotationPolicy{MinAcks: 2, AckTimeout: time.Hour, GracePeriod: 30 * time.Minute})
out, _ := svc.Acknowledge(ctx, r.ID, "app-1", "req-123", payload) // 幂等确认
err   := svc.CancelRotation(ctx, r.ID, "ops")                      // 取消（仅 collecting 时有效）
plain, _ := svc.Read(ctx, "db-password", v.ID, "app-1", "reason")  // 受控读取
st, _  := svc.Status(ctx, "db-password")                           // 状态查询（不含密文）
err   =  svc.Sweep(ctx)                                            // 推进超时/宽限期
```

错误统一为 `*secretrotation.Error`，用 `IsKind(err, secretrotation.KindConflict)` 等方式分类判断。

## 持久化

`Store` 接口负责状态快照与审计日志的持久化：

- `MemoryStore`：进程内实现（深拷贝模拟持久化），用于测试；
- `FileStore`：状态写入 `state.json`（临时文件 + rename 原子提交），审计追加写入 `audit.jsonl`，文件权限 0600。

## 运行测试

    go test -race ./...

测试覆盖：完整轮换生命周期、确认幂等与冲突、快照冻结、迟到确认/取消、超时、并发终态唯一性、明文不泄漏、文件持久化重启恢复、参数校验。
