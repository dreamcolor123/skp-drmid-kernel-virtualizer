# Changelog

## 1.4.0-rc1

- 删除 TEE/SMCInvoke 后端，仅保留 Widevine HAL 出站 Binder 全局后端。
- Resolver 改为面向 Android 14+、ARM64、64 位 Binder、Linux 6.1+ 的运行时能力发现；
  classic 与 Rust 只作为能力类别，不再按 6.6/6.12 小版本选择硬编码画像。
- 增加 live Binder FD、`file->f_op`、Binder 符号、core text 指针和 256 字节入口指纹
  的交叉校验，以及 BTI/PAC/栈帧/可重定位前缀语义分类。
- 增加 Hook-site/veneer/trampoline 共存门禁：拒绝入口首条直接 `B`、SDK allocated
  trampoline 和 core text 外分支目标，避免同一开机叠加 Hook。
- Kernel Context ABI 保持 20，Control IPC 保持 `DRMIPC20` / v5，Runtime control
  保持 `DRMCTL18` / v3；升级不轮换现有 seed、ID 或配置 generation。
- 固定使用 SKRoot Pro SDK 4.5.4 上游提交
  `90a28f81b85042b2483a62630455f1d70e334d6f` 及静态库哈希。
- 6.6 真实采集 Fixture、6.12 原始入口和合成 6.1 classic/Rust 入口统一走同一解析路径；
  全量离线回归 `163/163 PASS`。
- Linux 6.12 / Android 16 已完成 Resolver-only、Dry-run 100 次与 Write 200 次真机
  验收，所有 write/copy/boundary/pending fault 为 0，重启后原始入口恢复。

## 1.3.0-rc2

- 将构建依赖升级到 SKRoot Pro SDK 4.6.0。
- 通过浅层 Git submodule 连接官方上游仓库，并固定到提交
  `843b8ab32905e653d5959683cfca328883e9076c`，避免浮动分支破坏可复现构建。
- 发布守卫固定校验 SDK 静态库 SHA-256；未初始化 submodule 时给出明确命令。
- 缺少本地设备 AIDL 探针素材时跳过该可选探针，公开仓库克隆后仍可构建正式模块。
- WebUI 离开前台后进入整页终止状态，并关闭会话与监听端口。

## 1.3.0-rc1

- 增加 Widevine `si_object_do_invoke` / `free_si_object` TEE 后端，覆盖 OEMCrypto/SMCInvoke 直连路径。
- Binder 与 TEE 共享同一 mode、seed/profile、generation 和虚拟 ID；TEE 侧按 Widevine loader/controller/TA 对象链做 fail-closed 识别。
- Control IPC 升级为 `DRMIPC19` / v4 / 352 字节，Kernel Context 升级为 ABI 19。
- 全局调用路径不使用包名、UID/EUID、PID 或 TGID 过滤；保留 HAL identity 集合用于 Binder 出站关联。
- 新增固定容量 TEE 对象表、`free_si_object` 地址清理和无阻塞热路径发布守卫。
- 增加 6.12 Dry-run/Write 双路径真机验收记录，以及单会话 OEMCrypto 直连验收工具。

## 1.2.0

- 将虚拟化位置迁移到 Widevine HAL 的 Binder 出站回复路径，全局共享同一虚拟 ID。
- 移除应用包名、目标 UID、多应用列表和应用标签 helper，不再按调用应用匹配。
- 精确关联 `IDrmPlugin` transaction 11 的 `deviceUniqueId` 请求与 32 字节回复。
- 增加 Widevine HAL 身份交叉核验、pidfd 生命周期监控和重启热恢复。
- Runtime control 升级为 v3；v2 迁移保留现有 ID、模式、generation 和指纹。
- WebUI 收敛为“DRM ID虚拟化”开关，以及固定值、随机值、自定义三种 ID 来源。
- 页面退到后台、关闭或心跳超时后自动结束 WebUI 会话和监听端口。
- Kernel Context ABI 更新为 18，Linux 6.6/6.12 resolver 继续严格匹配并 fail-closed。

## 1.1.3-rc2

- 在全局 `binder_ioctl` Hook 入口增加严格有界的 installer/target/app UID 快速门。
- 核心服务 UID 在计数、copy、stream parser、事件环和关联表前直接旁路。
- 使用寄存器物化应用 UID 下限 `10000`，修复 AArch64 immediate 编码错误。
- 生产 control socket 改为阻塞等待，移除空闲状态每 200 ms 周期唤醒。
- Kernel Context ABI 更新为 17，总大小保持 97,704 bytes。
- 增加入口门顺序、边界、热配置语义和空闲唤醒发布守卫。

## 1.1.2

- 修复目标应用反复结束、重新打开后虚拟 DRM ID 偶发回落。
- pending/plugin 固定关联表升级为八路有界 LRU，总容量保持 256 项。
- pending 关联增加 task pointer、PID、TGID 联合校验。
- 桶满时回收最旧残留项，不因已退出客户端长期占位而拒绝新关联。
- Kernel Context ABI 更新为 16，总大小保持 97,704 bytes。
- 发布守卫和离线 Fixture 同步覆盖八路寻址、LRU 回收及诊断输出。

## 1.1.0

- 增加 Linux 6.6 classic Binder 严格 profile。
- 保留 Linux 6.12 classic/Rust Binder 支持。
- Linux 6.6.89 完成真机验收。
