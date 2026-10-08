# 文件接收总时限审查（2026-10-08）

## 问题

Fabric 与 NeoForge 的 `OptionalSharing.receiveFile` 原先将 `FileStreamCodec.read` 交给与公钥校验、文件发送准备共用的单个 `SharingWorker`。读取会等待文件内容和经过认证的 EOF，期间工作线程保持忙碌。

流 API 原有 60 秒空闲超时，但每个成功解密的非空记录会刷新活动时间。已导入公钥且未被设为不信任的远端，在用户启用了文件接收时，可持续每隔不到一分钟发少量有效内容，或缓慢补齐文件头，长期占用该工作线程，阻止其他文件任务及接收公钥的处理。10 MiB 大小限制不能限制这种耗时；API 会话 TTL 仍提供另一层限制，默认 60 分钟，因此不能将原实现描述为完全无任何时间边界。

这属于共享功能的可用性问题。文件保存仍需用户明确接受并重新检查身份；没有发现该路径可绕过同意写盘、执行文件或绕过签名/AEAD。

## 修复

新增两个加载器共用的 `FileReceiveTask`，从接纳文件流时起使用 `System.nanoTime()` 计算固定两分钟总时限，数据进展不续期。客户端 tick 到期时使 socket 失败，唤醒阻塞的文件读取；原有工作线程完成回调释放忙碌状态。读取成功返回前也检查时限，防止超过期限后在下一个 tick 前完成的内容生成文件 offer。

已及时读取成功的任务不会因为 UI 完成回调排队而被超时取消。切换设置和断开连接继续走取消路径；清理回调按任务对象判断，避免清除后来接纳的任务。原有文件大小限制、身份检查、用户同意、文件名净化与安全写盘保持不变。

网络格式和公开流 API 没有改变；普通 API 和反向转发仍可在有数据进展时长期使用。`Krypt04mcg-plugin` 与 `k04m-reverseforward` 无需为本次修复同步代码。极慢的合法文件接收也会在两分钟后被取消，需重试。

## 验证

五项新增回归测试使用可控单调时钟和真实 `KryptSocket`/`SharingWorker`，验证：

- 第 59、118、120 秒的非空数据不能刷新总时限，到期释放工作线程，随后新任务可成功接收。
- 完整内容但缺少认证 EOF 的读取会到期取消。
- 超时后才完整到达的数据，即使没有先执行 tick，也不能返回文件 offer 的数据。
- 及时成功的读取不会因 UI 回调延迟被误取消。
- 主动取消唤醒读取并释放工作线程。

Fabric `gradle build test` 成功，明确选择的八套测试共 47 项全部通过，失败、错误和跳过均为 0。选择包括 `FileReceiveTaskTest`、`FileStreamCodecTest`、`SharingWorkerTest`、`FileSharingLockTest`、`DataTransferServiceTest`、`KryptSocketTest`、`ChannelCryptoTest`、`OptionalTransferAssemblerTest`，用 `--tests` 分别指定，`--no-daemon --max-workers=2`。现有流测试涵盖 2 MiB 文件读取、缓冲背压、篡改、重放、认证 EOF 和会话恢复。

NeoForge `gradle -p neoforge build --no-daemon --max-workers=2` 成功，九套测试共 64 项全部通过，失败、错误和跳过均为 0。已将新增五项文件接收测试纳入该加载器的共享回归测试选择，实际执行了这些用例。

Java 25、Gradle 9.8.0。实际游戏联机未在本轮运行；反复发起新的合法接收任务仍可能骚扰用户，本次只限制每个文件任务的持续时间，不宣称全面防御洪泛。

本轮再次尝试读取 GitHub Dependabot 告警详情，`api.github.com` 返回 `Forbidden`，没有获得受影响依赖和版本范围。此前主项目推送报告的 18 项依赖告警（含 1 项严重、4 项高危）不能视为已解决。
