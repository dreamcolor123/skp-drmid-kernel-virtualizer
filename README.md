# SKP DRM ID Kernel Virtualizer

面向 SKRoot Pro 的 Android 14+ / ARM64 纯内核 DRM ID 虚拟化模块。

本分支版本：**1.2.0**

`1.2.0` 使用 Widevine HAL 出站 Binder Hook。所有通过已严格识别的 Widevine HAL
读取 `deviceUniqueId` 的调用共享当前同一个虚拟 ID，不再配置应用包名或目标 UID。

## 支持范围

- Android 14+
- ARM64、64 位 Binder
- Linux 6.12 优先
- Linux 6.6 使用已冻结的严格 resolver profile
- SKRoot Pro SDK 4.5.4

Linux 6.6/6.12 均执行内核版本、Binder backend、live symbol 和入口指纹联合校验；
未知内核构建在安装 Hook 前停止。

## 实现路径

```text
Widevine HAL 收到 BR_TRANSACTION
  -> 匹配 IDrmPlugin / transaction 11 / deviceUniqueId
  -> Pending 栈记录请求与 HAL identity generation
  -> HAL 发送 BC_REPLY 或 BC_REPLY_SG
  -> 校验 status=0、length=32、Parcel 边界和活动配置
  -> Dry-run 只计数；Write 对 HAL 出站 Parcel 做 32 字节等长覆盖
```

非活动 HAL TGID 在计数器、Pending 栈和用户内存复制之前直接进入原始
`binder_ioctl`。后端不使用应用侧 Binder 接收页、应用 UID 门禁、page-pin、线性
映射换算或插件句柄表。

## 主要特性

- 全局虚拟化：所有已确认的 Widevine HAL 调用共享一个虚拟 DRM ID。
- 精确关联：只处理指定接口、事务、属性及合法 32 字节回复。
- 三种 ID 来源：固定派生、一次性随机生成、64 位十六进制自定义值。
- 原子热发布：配置写入 inactive slot 后通过 STLR 切换，不重装 Hook。
- HAL 热恢复：pidfd 监控退出事件，重启后重新发现且不轮换当前虚拟 ID。
- 有界执行：身份集合、Pending 表和解析长度均有固定上限，无动态内存分配。
- Fail-closed：身份、ABI、指纹、记录 CRC 或回复格式不匹配时不写入。
- 低空闲开销：稳定阶段通过 pidfd 和 control socket 阻塞等待，不做周期扫描。
- WebUI 收口：页面退到后台、关闭或心跳超时后结束会话和监听端口。

## 配置与 ABI

- Kernel Context ABI：18
- Runtime control：`DRMCTL18` / v3 / 128 字节
- Control IPC：`DRMIPC18` / v3 / 200 字节
- RuntimeConfigSlot：96 字节
- 虚拟 ID 长度：32 字节
- 固定派生域：`global-widevine-v1`
- HAL 身份上限：4

v2 → v3 迁移保留现有 ID、mode、generation、seed generation 和 fingerprint，
丢弃旧 target 字段。旧 target config、runtime v1/v2 与 label helper 仅在 v3 配置
验证通过后收敛。

## WebUI

运行模式使用“DRM ID虚拟化”单一开关：

- 已关闭：对应 `mode=dry`，仅观察链路，不修改返回内容；
- 已开启：对应 `mode=write`，替换已严格关联的 32 字节回复。

ID 来源提供固定值、随机值和自定义三项。未选择来源时内部使用 `keep`，只调整运行
模式；成功应用一次来源操作后清空临时选择，避免误触造成 ID 再次轮换。

## 目录

```text
module_main.cpp              SKP 模块入口与 daemon 主流程
binder_ioctl_resolver.*      Binder backend 与严格内核 profile
binder_hook_builder.*        ARM64 Hook 构建与 Binder stream 解析
hal_identity.*               Widevine HAL 身份发现与生命周期监控
kernel_context.h             Kernel Context ABI
runtime_control.*            双槽全局 runtime config 与迁移
control_ipc.*                Control Socket v3
web_ui.cpp / webroot/        WebUI 后端与页面
tests/                       离线 Fixture
```

## 构建

仓库只保存模块源码，不提交 SKP SDK 静态库、NDK 输出、设备预编译库、日志或发布
ZIP。将仓库放在 SKRoot Pro SDK 的 `testModule` 目录，使其与
`kernel_module_kit` 并列：

```text
testModule/
├── kernel_module_kit/
└── skp-drmid-kernel-virtualizer/
```

构建依赖：

- Android NDK 26.3.11579264
- Android SDK Platform 35 / Build Tools 35.0.0
- JDK 17

Windows：

```bat
set NDK_ROOT=C:\path\to\android-ndk-r26d
set ANDROID_SDK_ROOT=C:\path\to\Android\Sdk
set JAVA_HOME=C:\path\to\jdk-17
clean.bat
build.bat
python package.py
```

## 离线测试

```bash
python3 -m unittest discover -s tests -v
```

源码 Fixture 覆盖 Binder stream、HAL 身份、Pending 并发、Runtime v3、迁移、文件
生命周期、WebUI 状态与 Linux 6.6/6.12 resolver。SDK 哈希、二进制身份和 ZIP 可复现
检查在对应本地构建输入存在时执行。

作者：斓梦语
