# 本地状态文件安全审查（2026-10-08）

本轮继续检查本地权限与持久化边界。确认并修复主项目群组、已发送分片缓存和解密/旧交换重放历史的存储缺口。相关反向转发授权文件的问题与修复记录在 `k04m-reverseforward` 仓库同名文档中。

## 问题与修复

`GroupService` 和 `SentMessageCacheService` 原先直接使用 `Files.writeString`，会跟随预先放置的符号链接写入目标，也不显式设置私有权限或通过临时文件替换。三个服务读取 JSON 时均未拒绝链接；悬空链接还会被 `Files.exists` 当作没有历史状态。

现在在判断文件是否存在之前检查目标和父目录路径，拒绝符号链接、悬空链接和特殊存储路径。读取已有文件前收紧到所有者权限；群组和已发送分片缓存的写入复用 `SecureFiles.atomicWrite`，采用私有目录和随机临时文件替换。解密历史已有安全写入，本次补齐读取检查。

这些风险需要本地文件被预先替换、其他本地用户可访问原文件，或恢复了不安全的存储路径。没有证据表明远端玩家能单独创建这些链接；本次不将其描述为远程任意文件写入或远程鉴权绕过。所有者权限也不防御以同一操作系统账户运行的恶意进程，路径检查不能宣称完全消除并发文件系统竞态。

JSON 格式、分片内容、收件人指纹绑定和旧交换重放记录不变。普通已有文件可以直接读取；此前使用符号链接共享的配置需要迁移到普通本地目录。没有更改网络协议、公开 API 或服务端中继，`Krypt04mcg-plugin` 本轮无需同步修改。

## 验证

- 修复前，最初三项新测试中的链接读写、悬空链接读取两项失败；权限测试在本机默认 umask 下通过，后续增加了放宽权限后读取会重新收紧的断言。
- 修复后，四项存储测试覆盖三个服务的最终文件链接、悬空链接、父目录链接、所有者权限、JSON 往返和跨实例旧交换重放检查，全部通过，无跳过。
- Fabric `gradle build test` 成功。明确选择的 11 套、70 项测试全部通过，失败、错误、跳过均为 0，涵盖上述存储、缓存重发信任、密钥/信任、会话/握手和私密存储。
- NeoForge `gradle -p neoforge build --no-daemon --max-workers=2` 成功，8 套、59 项测试全部通过，失败、错误、跳过均为 0；其既有测试选择没有包含本轮新增的四项存储测试。
- Fabric 选择：`PlaintextStateStoreSecurityTest`、`ChatResendTrustTest`、`KeyStoreServiceTest`、`KeyTrustServiceTest`、`SessionServiceTest`、`HandshakeFailureRecoveryTest`、`HandshakeEpochCommitTest`、`HandshakeStateMachineTest`、`ChatSessionIdentityTest` 和 `dev.krypt04mcg.util.*`，用 `--tests` 分别指定。Java 25，Gradle 9.8.0，`--no-daemon --max-workers=2`。

这仍是针对性人工审查。全量后量子参数测试、实际游戏联机、Windows ACL/DPAPI 和 GitHub 依赖告警未在本轮验证；既有依赖告警不能据此视为已修复。
