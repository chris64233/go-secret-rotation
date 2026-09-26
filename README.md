# go-secret-rotation

需要多个消费者确认的应用密钥轮换编排服务（Go 库）。密钥按**不可变版本**
管理；每次轮换先建立“待激活”新版本并**冻结**本次必须确认的消费者集合，
达到确认门槛后新版本才能原子激活，旧版本同时进入只读宽限期，宽限期结束
后旧版本读取必然失败。

开发环境：Go 1.23.0，无第三方依赖。

## 核心模型

### 版本状态机

```
pending ──(轮换激活)──► active ──(被更新版本取代)──► grace ──(宽限期结束)──► retired
   │                       ▲                              ▲
   └─(轮换取消/超时)─► retired                           读取时原子退役
```

- 版本号单调递增、内容不可变：新版本只能通过轮换产生，任何状态迁移都不
  修改版本承载的密钥材料。
- `pending` 版本不可读；`active` 全局唯一；`grace` 旧版本只读且有明确的
  `RetireAt` 时刻；`retired` 后读取一律返回 `expired`。
- 密钥未配置宽限期（`GracePeriod == 0`）时，旧版本在新版本激活的同一刻
  立即退役。

### 轮换状态机

```
                 ┌──► activated（新版本 active，旧版本 grace/retired）
pending ─────────├──► cancelled（待激活版本废弃）
                 └──► timed_out（超过截止时间，待激活版本废弃）
```

- `activated` / `cancelled` / `timed_out` 互为竞争的**终态**。并发调用下
  只有一个终态能够落库：激活成功后的迟到取消不能回退版本，超时也不会
  重复终结。
- 发起轮换时冻结 `RequiredConsumers` 快照与超时截止时刻；之后消费者
  目录如何变化都不改变本次门槛。

## 使用方式

```go
package main

import (
    "context"
    "fmt"
    "time"

    sr "github.com/chris64233/go-secret-rotation"
)

func main() {
    ctx := context.Background()

    // 生产环境主密钥应来自 KMS/HSM；此处仅为示例。
    enc, err := sr.NewAESGCMEncryptor([]byte("0123456789abcdef0123456789abcdef"))
    if err != nil {
        panic(err)
    }
    svc := sr.NewService(
        sr.NewMemoryStore(), // 生产环境替换为持久化 Store
        enc,
        sr.NewMemoryAuditSink(),
        nil, // time.Now
    )

    // 1) 建立密钥（首个版本创建即激活），旧版本允许 30 分钟宽限。
    if _, err := svc.CreateKeyVersion(ctx, sr.CreateKeyInput{
        Name:        "payments-db",
        Plaintext:   []byte("initial-secret"),
        GracePeriod: 30 * time.Minute,
        Readers:     []string{"billing", "checkout"},
    }); err != nil {
        panic(err)
    }

    // 2) 发起轮换：冻结必须确认的消费者快照与 1 小时超时。
    rot, err := svc.StartRotation(ctx, sr.StartRotationInput{
        KeyName:      "payments-db",
        NewPlaintext: []byte("rotated-secret"),
        Policy: sr.Policy{
            RequiredConsumers: []string{"billing", "checkout"},
            Timeout:           time.Hour,
        },
        RequestID: "req-start-0001",
    })
    if err != nil {
        panic(err)
    }

    // 3) 每个消费者加载新版本后确认（消费者+轮换幂等）。
    for _, consumer := range []string{"billing", "checkout"} {
        if _, err := svc.Acknowledge(ctx, sr.AcknowledgeInput{
            KeyName:       "payments-db",
            RotationID:    rot.ID,
            Consumer:      consumer,
            LoadedVersion: rot.PendingVersion,
            RequestID:     "req-ack-" + consumer,
        }); err != nil {
            panic(err)
        }
    }

    // 4) 门槛达成后原子激活；旧版本进入宽限期。
    if _, err := svc.Activate(ctx, "payments-db", rot.ID, "req-activate-0001"); err != nil {
        panic(err)
    }

    // 受控读取（唯一返回明文的通道）。
    view, err := svc.ReadSecret(ctx, "payments-db", 0, "billing") // version<=0 表示当前 active
    if err != nil {
        panic(err)
    }
    fmt.Println("active version:", view.Version)

    // 状态查询只返回元数据，不含任何密钥材料。
    info, _ := svc.Status(ctx, "payments-db")
    for _, v := range info.Versions {
        fmt.Printf("v%d %s\n", v.Number, v.Status)
    }
}
```

后台可周期性调用 `SweepTimeouts(ctx)` 自动终结超过截止时间的轮换。

## API 一览

| 方法 | 说明 |
| --- | --- |
| `CreateKeyVersion` | 建立密钥与首个不可变版本（创建即激活），明文仅经 `Encryptor` 加密后落库 |
| `StartRotation` | 建立 pending 新版本，冻结确认消费者快照与截止时刻；同密钥同时只允许一个未终结轮换 |
| `Acknowledge` | 消费者确认已加载待激活版本；按“消费者 + 轮换”幂等 |
| `Activate` | 门槛达成后原子激活新版本，旧版本同时进入宽限期（或立即退役） |
| `Cancel` | 取消未终结轮换并废弃 pending 版本；终态后迟到取消被拒绝 |
| `ProcessTimeout` / `SweepTimeouts` | 终结超过截止时间的轮换 |
| `ReadSecret` | 唯一返回明文的受控读取通道，带读者白名单、版本与宽限期校验 |
| `Status` | 查询全部版本/轮换的非敏感状态；顺带应用到期的超时与退役 |

## 幂等与冲突规则

- **发起轮换**：相同 `RequestID` 重放返回同一轮换；同请求号但快照集合或
  超时不同，返回 `conflict`。
- **消费者确认**：
  - 幂等键为“消费者 + 轮换”：同一消费者重复确认安全返回且不重复计数；
  - 同一 `RequestID` 提交不同内容（不同消费者或不同加载版本号）返回
    `conflict`；
  - 消费者不在发起时冻结的快照集合内 → `permission_denied`，确认不计数；
  - 声明加载的版本号与待激活版本不一致 → `invalid_argument`；
  - 轮换终态后的迟到确认 → `failed_precondition`，不推进任何状态。
- **激活/取消**：重复调用天然幂等；请求号被不同动作复用返回 `conflict`。

## 并发与终态保证

所有变更都通过 `Store.CompareAndSwap(expected, next)` 的乐观锁完成：
服务层读取状态 → 在深拷贝上计算下一状态 → 按修订号条件提交，冲突即
重试。因此即使激活、取消、超时来自不同 goroutine/进程同时发生：

- 轮换只会进入**恰好一个**终态，终态迁移审计事件恰好一条；
- 激活后迟到取消返回 `failed_precondition`，`active` 版本不回退；
- 宽限期到期在读取路径中以“先原子退役落库、再返回过期错误”的方式处理，
  保证此后任何读取都失败。

## 错误分类

错误统一为 `*secretrotation.Error`，用 `secretrotation.ErrorCode(err)`
取码，调用方按码而非文本处理：

| Code | 场景 |
| --- | --- |
| `invalid_argument` | 参数缺失/非法、加载版本与待激活版本不符 |
| `not_found` | 密钥、版本或轮换不存在 |
| `already_exists` | 同名密钥重复创建 |
| `conflict` | 请求号被不同内容/不同动作复用 |
| `failed_precondition` | 门槛未达成即激活、对终态轮换迟到取消/确认、读取 pending 版本 |
| `permission_denied` | 非快照成员确认、非白名单消费者读取 |
| `expired` | 版本已退役/宽限期结束、轮换已超时 |
| `internal` | 加解密或持久化失败（详情不含密钥材料） |

## 机密性保证

- 明文只出现在三处：入参、`Encryptor.Encrypt/Decrypt` 的边界、
  `ReadSecret` 的返回值。
- 持久化状态中只保存 AES-256-GCM 密文（随机 nonce），并以
  “密钥名 + 版本号”作为 GCM 附加数据，防止密文跨密钥/跨版本搬运。
  `MemoryStore` 仅用于单机/测试，生产环境需实现自己的持久化 `Store`。
- 审计事件（`AuditSink`）与全部错误消息只含密钥名、版本号、消费者等
  元数据，禁止出现明文或密文片段。测试以明文探针扫描持久化状态、
  审计事件和错误文本来固化这一保证。

## 测试

```sh
go test ./...            # 全部测试
go test -race ./...      # 含竞态检测（终态竞争用例）
go test -cover ./...     # 覆盖率
```

测试覆盖：完整轮换生命周期、确认幂等与请求号冲突、快照冻结不随成员
变化、激活/取消/超时三方并发只产生一个终态、宽限期到期读取必然失败、
静态加密往返与防搬运、以及明文不泄漏到持久化/审计/错误文本。
