# SKP DRM ID Kernel Virtualizer

## 当前正式版

`1.4.0` 在 Binder-only 全局后端上引入运行时 Binder 能力发现，面向
Linux 6.1+ 统一解析并移除按小版本固定入口序言放行的版本矩阵。普通应用经 Java
`MediaDrm` 或 NDK `AMediaDrm` 读取 `deviceUniqueId` 时，共享当前同一个虚拟 ID；
配置不关联应用包名、UID/EUID、PID/TGID 或调用者身份。

WebUI 使用一个“DRM ID虚拟化”开关，以及“固定值、随机值、自定义”三种 ID 来源。
未选择 ID 来源时只切换运行模式并保持当前 ID；显式选择来源后才更新 ID，应用完成
后清空临时来源选择。

支持范围：

- Android 14+；
- ARM64、64 位 Binder；
- Linux 6.1+，以运行时能力校验作为最终门禁；
- SKP SDK 固定为 4.6.1。

## 唯一数据路径

```text
普通应用 Java MediaDrm / NDK AMediaDrm
  -> Widevine HAL 收到 BR_TRANSACTION
  -> 精确匹配 IDrmPlugin / transaction code 11 / deviceUniqueId
  -> 当前 Binder 线程 Pending 栈记录请求和 HAL identity generation
  -> HAL 发送 BC_REPLY 或 BC_REPLY_SG
  -> 原始 binder_ioctl 前弹出并关联 Pending
  -> 校验 status=0、length=32、Parcel 边界和活动配置
  -> Dry-run 只计数；Write 对 HAL 自己的出站 Parcel 执行 32 字节等长覆盖
```

非 HAL TGID 在首个计数器、栈分配和用户内存复制之前直接执行原始
`binder_ioctl`。后端不使用应用侧 Binder 接收页、page-pin、线性映射换算、插件
句柄表或任何 TEE/SMCInvoke Hook。

## HAL 身份生命周期

daemon 通过 `/proc` 同时核验 Widevine HAL 的：

- `exe` 与 `cmdline`；
- DRM 服务 UID；
- SELinux Widevine DRM 域；
- Binder FD；
- 非零 TGID。

身份集合最多 4 项，排序、去重后写入 inactive identity slot，再通过 STLR 发布。
稳定运行时以 pidfd 和控制 socket 一起阻塞等待，不做周期进程扫描。HAL 退出后先
发布空身份集，再在缺失阶段按 50–2000 ms 有界退避发现新进程；缺少 pidfd 支持时
使用 5 秒低频 `/proc` 兼容监控。HAL 重启只改变 identity generation，不改变配置
generation 或当前 ID。

## 配置、ABI 与迁移

- Kernel Context ABI：20；
- Runtime control：`DRMCTL18` / v3 / 128 字节；
- Control IPC：`DRMIPC20` / v5 / 200 字节；
- Control socket：`drmid_control_v5.sock`；
- RuntimeConfigSlot：96 字节，仅保存 generation、seed、fingerprint、mode 和 ID；
- ID 长度固定为 32 字节；
- 派生域固定为 `global-widevine-v1`；
- v2→v3 迁移保留当前 ID、mode、generation、seed generation 与 fingerprint；
- 从 `1.3.0-rc1` 升级不会轮换 seed、当前虚拟 ID 或配置 generation。

WebUI 提供固定值、随机值、自定义三种 ID 来源和 HAL 诊断。页面隐藏、失焦、冻结、
关闭或心跳失效后，会话和监听端口自动结束；当前页面进入不可恢复的整页“后台已
退出，请重新从管理器打开”状态，不在恢复前台时自动重连。

## 1.4.0 通用能力发现

- SDK 动态解析 `task/files/fdtable` 偏移，并通过 live Binder FD 取得真实对象；
- 使用 `binder_fops` / `binder_ioctl` 与 Rust Binder 对应符号做有界扫描和交叉校验；
- 读取 256 字节入口并使用 BTI、PAC、栈帧、frame-link 和可重定位前缀语义门禁；
- classic/Rust 只作为能力类别，不再绑定内核小版本；
- 未满足符号、内核文本、入口语义或 Hook 前缀条件时保留原始 Binder 路径；
- 私有 `DRMCAP21` 记录向 WebUI 提供内核、解析来源、能力标志与入口指纹，
  Control IPC 保持 `DRMIPC20` / v5 / 200 字节。

## 构建与离线验收

首次克隆时初始化固定的上游 SDK：

```bash
git clone --recurse-submodules https://github.com/dreamcolor123/skp-drmid-kernel-virtualizer.git
cd skp-drmid-kernel-virtualizer
```

已有克隆执行：

```bash
git submodule update --init --depth 1
```

SDK 固定到 SKRoot Pro 4.6.1 上游提交
`68020a4e265dcfaa875e97f54f14f07422b9f1d2`。`build.bat` 会先运行
`prepare_sdk.py`，核验提交与静态库 SHA-256
`5b304a9d7e1c2d5d8aa2e7d2a95710d37b1f261e1a92ffe640737d747ed93f91`，再复制到未
纳入版本控制的 `.sdk-cache/` ASCII 路径供 Windows NDK 使用。

```bash
/mnt/c/Windows/System32/cmd.exe /d /c clean.bat
/mnt/c/Windows/System32/cmd.exe /d /c build.bat
python3 -m unittest discover -s tests -v
python3 package.py
```

验收覆盖：

- HAL method/interface/property 精确关联；
- BC/BR stream 边界与 32 字节回复改写；
- Pending 并发、LIFO、锁竞争和 HAL generation 失效；
- HAL 身份交叉核验、pidfd 退出、空集发布、退避和兼容监控；
- Runtime v3 布局、CRC、v2 迁移保 ID 和双槽一致性；
- WebUI 全局状态、JavaScript 语法和退后台关端口竞态；
- TEE 源文件、符号、ABI 字段、WebUI 字段和二进制字符串全部缺失；
- 文件生命周期、SDK 4.6.1、ZIP 成员白名单和可复现打包；
- Linux 6.6/6.12 真实入口与合成 6.1 classic/Rust 入口语义回归；
- Linux 6.1+ 版本门槛、符号/live 交叉验证和未知入口降级。

当前 clean build 离线结果：`163/163 PASS`。

候选包：

```text
dist/module_drmid_kernel_virtualizer-1.4.0-arm64-run-once.zip
```

SHA-256：

```text
129d15927884c2a55599e1f24313875cd4de5f369744346c9cf85bde6f57242e
```

ZIP 固定只包含：

```text
libmodule_drmid_kernel_virtualizer.so
webroot/drmid_daemon
webroot/index.html
```

## 6.12 真机验收

Linux 6.12 / Android 16 已完成 Resolver-only、Dry-run 与 Write 验收：Dry-run 下
NDK 50 次与 AIDL 50 次均命中候选且零写入；Write 下 NDK 100 次与 AIDL 100 次
均命中同一活动配置并完成等长覆盖，write/copy/boundary/pending fault 均为 0。普通
重启后原始 Binder 入口与入口指纹恢复，设备临时文件清零。

Resolver 的 Hook-site 门禁会拒绝入口首条直接 `B`、SDK allocated trampoline 与
core text 外的 veneer 目标，避免同一开机叠加 Hook。首个真实 6.1 设备仍先执行
Resolver-only 只读探测，再安排 Dry-run。

开发和测试不更新、安装或卸载 SKP 环境，不修补或刷写 boot，也不在构建产物中
保存管理器凭据。
