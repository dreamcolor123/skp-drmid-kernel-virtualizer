# 1.1.3-rc2 Binder 解析框架与扩展指南

## 1. 文档目的

本文说明 `1.1.3-rc2` 中哪些代码可以作为 Binder 解析与返回值虚拟化框架复用，
哪些代码只属于 Widevine DRM ID 业务，以及开发新 handler 时需要补充哪些适配。

本分支固定在源码提交：

```text
05440226ca179f6a4f540b885a345d7e721ef2a1
```

目标平台：

- Android API 34+；
- ARM64、64 位 Binder；
- Linux 6.6 classic Binder；
- Linux 6.12 classic Binder / Rust Binder；
- SKRoot Pro SDK 4.5.4。

## 2. 定位：工程基线，而非通用 Binder 库

该版本已经实现一条完整的数据路径：

```text
定位并验证 Binder 内核入口
  -> 安装单一 binder_ioctl Hook
  -> 按当前调用者 EUID 快速路由
  -> 解析 BC/BR command stream
  -> 识别目标请求并建立 Pending 关联
  -> 在对应回复中验证 Parcel
  -> Dry-run 计数或等长写入
  -> 通过双槽配置在线切换策略
```

这条路径可以被重构为共享的 Binder core，但当前源码并没有把所有服务抽象成统一
handler 接口。现有解析逻辑针对 Widevine `deviceUniqueId` 的 interface、transaction
和 32 字节返回值编写。新功能不得仅替换字符串或 transaction code 后直接发布。

## 3. 可复用的基础设施

### 3.1 Binder 入口解析和版本门禁

`binder_ioctl_resolver.*` 提供：

- Linux 6.6/6.12 Binder backend 识别；
- live symbol、函数入口和指令指纹联合校验；
- 未识别内核构建时在安装 Hook 前停止；
- classic/Rust Binder profile 的严格区分。

新模块可以复用 resolver 结构和 fail-closed 门禁，但需要为新增内核构建提供独立
Fixture 和真机指纹，不能把未知入口当作兼容入口。

### 3.2 BC/BR 命令流处理

`binder_hook_builder.cpp` 已处理并验证以下基础能力：

- 遍历 Binder write/read command stream；
- 识别 `BC_REPLY`、`BC_REPLY_SG`、`BR_TRANSACTION`、
  `BR_TRANSACTION_SEC_CTX` 等命令；
- 校验 command、transaction header、buffer 长度和边界；
- 从当前 task/cred 读取 EUID；
- 对非目标调用快速返回原始 `binder_ioctl`；
- 在异常、竞争或格式不匹配时保留原始数据。

这些代码可以作为 command stream 层复用。目标服务的 interface token、transaction
code、参数和返回值格式属于 handler 层，必须单独实现。

### 3.3 请求与回复关联

现有 Pending/plugin 表具有：

- 固定容量、预分配存储；
- 八路有界 LRU 查找与残留回收；
- task pointer、PID、TGID 联合校验；
- generation 校验；
- 有界锁，竞争时放弃本次元数据而不阻塞原调用；
- 进程退出或地址复用后的失效处理。

该结构适合复用到“请求阶段识别调用者、回复阶段修改结果”的功能。新 handler 应使用
独立的事件类型和最小关联元数据，不应复用 Widevine handle 字段表达其他协议。

### 3.4 按应用路由

`app_catalog.*`、`target_config.*` 和 WebUI 已提供：

- 从设备枚举包名、UID、应用名称和图标；
- WebUI 应用选择；
- 最多 32 个目标包；
- 包名到 EUID 的解析；
- 排序、去重和 shared UID 识别；
- 配置 CRC、原子替换和 v1 -> v2 迁移；
- 任一目标解析失败时保留上一代完整规则。

这一层适合改造成观察者规则，例如：

```text
observer_packages[32]  接收虚拟视图的应用
hidden_packages[32]    从虚拟视图中移除的应用
```

多用户设备中，UID 同时包含 userId 和 appId。涉及工作资料或多个 Android 用户时，
必须明确规则是按完整 UID、appId 还是“包名 + 用户”生效。

### 3.5 运行时配置发布

`runtime_control.*` 和 `kernel_context.h` 使用双槽配置：

1. EL0 填充 inactive slot；
2. 校验完整 generation 和字段；
3. 使用 release 语义切换 active slot；
4. EL1 一次请求只读取同一代不可变配置。

因此目标应用、运行模式和业务值可以在线更新，无需重复安装 Hook。新模块必须分配自己的
magic、record version、Kernel Context ABI 和 Control IPC，不得继续使用 DRM 协议名。

### 3.6 运行模式和诊断

现有控制面可复用：

- Dry-run：只识别、关联和计数，不写入用户 Parcel；
- Write-test：满足全部 profile 后执行写入；
- 事件环、命中/降级/竞争计数；
- 阻塞式 control socket，空闲时不做 200 ms 周期唤醒；
- WebUI 会话、应用选择器和状态展示。

新 handler 首个真机阶段应只启用 Dry-run，并证明请求数、回复数和生命周期守恒后再
开放写入。

## 4. Widevine 专用代码

以下逻辑是当前业务实现，不属于通用 Binder core：

- Widevine UUID 和 factory 请求识别；
- `deviceUniqueId` 字符串及对应 transaction profile；
- Widevine plugin handle 生命周期；
- 32 字节 Device ID 长度约束；
- 固定值、派生值和自定义 DRM ID；
- DRM 专用 fingerprint、seed domain 和统计字段。

扩展其他服务时应把这些逻辑移动到 `handlers/widevine_drmid`，而不是让新协议继续增加
到同一大段汇编生成函数中。

## 5. 推荐的重构边界

```text
binder_core/
  resolver.*             内核版本、backend、符号和入口指纹
  hook_broker.*          单一 Hook 的 handler 分发
  command_stream.*       BC/BR 命令迭代与边界检查
  transaction_tracker.*  请求/回复关联及生命周期
  caller_router.*        EUID、用户和观察者规则
  parcel_io.*            安全读取、等长写入和对象偏移工具
  runtime_slots.*        双槽配置发布

handlers/
  widevine_drmid.*       当前已验证的 DRM ID handler
  package_visibility.*   PackageManager 视图 handler
  settings_view.*        Settings/Provider handler
```

`hook_broker` 应保证同一内核入口只安装一次 Hook。每个 handler 返回以下三态之一：

```text
not-matched   与本 handler 无关，继续分发
observed      Dry-run 命中但不修改
handled       校验完成并已处理，停止重复修改
```

任何解析错误都应回到原始 Binder 结果，并增加有界诊断计数。

## 6. 应用列表可见性示例

`1.1.3-rc2` 可以作为应用列表可见性模块的起点，但分支当前没有实现该功能。至少需要
新增：

1. PackageManager/LauncherApps 的 interface token 和 transaction profile；
2. `getInstalledPackages`、`getInstalledApplications`、
   `queryIntentActivities` 等列表接口解析；
3. `getPackageInfo`、`getApplicationInfo` 等精确查询行为；
4. `ParceledListSlice` 分片、continuation 和版本差异；
5. 可变长度 Parcel 重建、count/length 修正；
6. Binder object offsets 的重新计算；
7. Android 14/15/16及厂商实现 Fixture；
8. 多用户、shared UID、isolated UID 和隐藏应用自身排除规则。

推荐数据路径：

```text
观察者应用发出 PackageManager 查询
  -> 请求阶段记录 sender EUID、接口和 transaction
  -> system_server 生成真实回复
  -> 回复阶段命中 Pending
  -> 严格解析列表及对象偏移
  -> 移除当前观察者规则中的隐藏包
  -> 重建并验证 Parcel
  -> 返回过滤后的视图
```

PackageManager 过滤只代表“应用列表视图”。`/data/app`、`/data/user`、`/proc`、
UsageStats、ActivityManager 和已知路径访问是不同数据面，需要独立适配和状态展示。

## 7. 多模块共存限制

`binder_ioctl` 是全局热入口。两个模块分别对同一地址安装独立 Hook，可能造成：

- 安装顺序依赖；
- trampoline 覆盖或卸载恢复错误；
- 双重解析和重复修改；
- 其中一个模块卸载后破坏另一个模块；
- 所有 Android Binder 调用进入额外热路径。

因此从本分支派生新 Binder 功能时应选择以下一种方案：

1. 单一 `hook_broker` 同时承载多个 handler；
2. 使用已验证的不同内部 Binder 目标；
3. 将功能合并为同一个模块和 Kernel Context。

在共存设计和卸载顺序经过验证前，不应把两个独立的 `binder_ioctl` Hook 同时作为正式
配置加载。

## 8. 与后续分支的区别

| 版本 | 主要路由方式 | 适合作为哪类基线 |
|---|---|---|
| `1.1.3-rc2` | 按包名/EUID选择应用，应用侧 Binder 请求/回复关联 | 按应用策略、应用视图和 Binder handler 框架 |
| `1.2.x` | Widevine HAL 全局 Binder 出站 | 全局 DRM ID，不需要调用应用识别 |
| `1.3.x` | HAL Binder + TEE 直连 | Widevine 全通路覆盖和 TEE 对象链 |

后续版本并非能力更低，而是为全局 DRM ID 删除了包名、UID和应用选择器。需要按应用
区分行为时，`1.1.3-rc2` 的代码结构更接近目标。

## 9. 新 handler 开发检查表

### 设计

- 分配独立 module ID、配置 magic、ABI 和 IPC 版本；
- 明确观察者、目标对象和多用户语义；
- 明确一个接口是等长修改还是需要重建 Parcel；
- 选择单 Hook broker 或不冲突的内部 Binder 目标。

### 解析

- 固定 interface token 与 transaction profile；
- 校验全部偏移、长度、对齐和最大上限；
- 覆盖普通 reply、SG reply、错误 reply 和分片；
- 未知版本、未知对象或畸形输入保持原始结果。

### 热路径

- 固定容量结构；
- 不动态分配；
- 查找和循环有明确上限；
- 非观察者在首次计数、copy 和 parser 前快速返回；
- 锁竞争直接降级，不等待 Binder 全局入口。

### 验证

- 先用离线 Parcel Fixture；
- 再进行真机只读画像；
- Dry-run 验证 request/reply/Pending 守恒；
- Write 仅在严格 profile 命中时开启；
- 测试服务重启、应用重启、shared UID、多用户和模块卸载；
- 记录非目标 Binder 性能和空闲唤醒基线。

## 10. 关键源码索引

| 文件 | 作用 |
|---|---|
| `binder_ioctl_resolver.*` | Binder backend 与严格内核 profile |
| `binder_hook_builder.*` | ARM64 Hook、command stream、关联和当前 Widevine handler |
| `kernel_context.h` | EL1固定容量状态、事件和双槽配置 |
| `app_catalog.*` | 设备应用目录、名称和图标 |
| `target_config.*` | 包名/EUID规则、CRC、迁移和原子落盘 |
| `runtime_control.*` | 运行配置与双槽发布输入 |
| `control_ipc.*` | daemon 与 WebUI 状态/控制协议 |
| `web_ui.cpp`、`webroot/` | 应用选择和运行状态界面 |
| `tests/` | Binder、配置、生命周期、锁和发布守卫 Fixture |

开发者应先保持当前提交可重复构建和测试，再把 Binder core 与业务 handler 分离；不要
直接在已验证的 Widevine parser 中交叉堆叠多个互不相关的 Parcel 协议。
