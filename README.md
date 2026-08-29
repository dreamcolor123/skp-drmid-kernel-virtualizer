# SKP DRM ID Kernel Virtualizer

面向 SKRoot Pro 的 Android 14+ / ARM64 纯内核 DRM ID 虚拟化模块。

当前稳定版：**1.1.2**

性能修复候选：**1.1.3-rc2**

## 支持范围

- Android API 34+
- ARM64
- Linux 6.6 classic Binder
- Linux 6.12 classic Binder / Rust Binder
- SKRoot Pro SDK 4.5.4

Linux 6.6 使用严格的内核版本、Binder backend、live symbol 地址和入口指纹联合
校验。当前已完成 Linux 6.6.89 真机验收；其他精确内核构建若不匹配已知 profile，
会在安装 Hook 前停止。

## 功能

- 在 Widevine `deviceUniqueId` reply 路径执行固定长度虚拟化
- 最多配置 32 个应用包名，EL1 使用排序去重后的 EUID 集合匹配
- Dry-run 与 Write-test 模式
- 稳定派生 ID 与自定义 32 字节 ID
- 双槽 runtime config 原子发布
- 包名解析失败时保留上一代活动配置
- WebUI 应用选择器、当前语言应用名称及图标
- WebUI 离开前台后关闭会话和监听端口
- 有界 Binder correlation 锁；竞争时丢弃本次元数据并保持原调用继续
- pending/plugin 固定表使用八路有界 LRU 回收，应用反复结束和重新启动时不会因
  遗留关联项耗尽桶位
- Binder 全局入口在进入计数、用户内存复制和命令解析前执行严格有界 EUID 门禁；
  核心服务 UID 直接调用原始 ioctl
- control daemon 在生产模式下阻塞等待连接，消除空闲期间每 200 ms 的周期唤醒

## 目录

```text
module_main.cpp              SKP 模块入口与 daemon 主流程
binder_ioctl_resolver.*      Binder backend 与严格内核 profile
binder_hook_builder.*        ARM64 Hook 构建与 Binder stream 解析
kernel_context.h             Kernel Context ABI
target_config.*              多包目标配置及迁移
runtime_control.*            双槽 runtime config
control_ipc.*                Control Socket v2
web_ui.cpp / webroot/        WebUI 后端与页面
tests/                       离线 Fixture
tools/                       离线记录辅助工具
```

## Binder 解析框架定位

`1.1.3-rc2` 不只是一个 DRM ID 功能快照。它还保留了按应用选择、EUID 路由、
Binder 命令流解析、请求/回复关联、双槽配置热切换和 WebUI 控制面，可作为开发其他
Binder 返回值虚拟化模块的工程基线。

这里的“框架”是指已经经过本项目验证的基础设施，而不是一个不区分 Android 版本、
Binder 服务和 Parcel 格式的通用解析库。当前业务 handler 只识别 Widevine
`deviceUniqueId`；扩展 PackageManager、Settings 或其他 Binder 服务时，仍需为目标
接口实现严格的 interface、transaction code、Parcel 布局和返回值校验。

可复用能力、版本边界、推荐拆分方式和扩展检查表详见：

- [1.1.3-rc2 Binder 解析框架与扩展指南](docs/BINDER_FRAMEWORK.md)

## 构建

本仓库只保存模块源码，不提交 SKP SDK 静态库、NDK 输出、设备预编译库、管理器日志
或发布 ZIP。

将仓库放在 SKRoot Pro SDK 的 `testModule` 目录，使其与
`kernel_module_kit` 并列：

```text
testModule/
├── kernel_module_kit/
└── skp-drmid-kernel-virtualizer/
```

需要：

- Android NDK 26.3.11579264
- Android SDK Platform 35 / Build Tools 35.0.0
- JDK 17

Windows：

```bat
set NDK_ROOT=C:\path\to\android-ndk-r26d
set ANDROID_SDK_ROOT=C:\path\to\Android\Sdk
set JAVA_HOME=C:\path\to\jdk-17
build.bat
python package.py
```

## 离线测试

```bash
python3 -m unittest discover -s tests -v
```

其中 SDK 固定哈希和历史发布 ZIP 检查仅在对应本地输入存在时执行；其余 ABI、
parser、配置、WebUI、锁和 Linux 6.6 profile Fixture 可直接运行。

## 发布冻结信息

- 版本：1.1.2
- Kernel Context ABI：16 / 97,704 bytes
- Control IPC：v2
- TargetConfig：v2
- Linux 6.6.89 backend：`classic_binder-6.6`
- Linux 6.6 prologue：`d503233f d10343ff a9077bfd a9086ffc`

作者：斓梦语

## 1.1.3-rc2 性能候选

- 增加 Binder 入口快速门：保留安装进程自检、当前目标 EUID 和普通 Android
  应用 UID；其他核心服务 UID 在触碰计数器、用户 header、事件环和关联表前旁路；
- 目标 EUID 集合仍按活动 runtime slot 热切换，无需重装 Hook；
- 将 Android 应用 UID 下限 `10000` 先装载到寄存器再比较，修复 rc1 使用
  AArch64 `CMP-immediate` 时的 `InvalidImmediate`；
- 生产 control socket 使用无限期阻塞 `poll`，有连接或信号时才唤醒；
- Kernel Context ABI 更新为 17，总大小保持 97,704 bytes。

## 1.1.2 更新

- pending 与 Widevine plugin handle 表由四路调整为八路，总容量仍固定为 256 项；
- 桶满时回收最旧关联项，避免应用进程退出后未完成的 Binder 生命周期长期占位；
- pending 命中同时校验 task pointer、PID 与 TGID，处理 task address 复用；
- plugin lookup 刷新 LRU 年龄，优先保留仍活跃的 handle；
- 所有查找与回收均严格限制在最多 8 项，无动态分配；
- 日志将相关 `collision` 语义明确为已恢复的 `reclaim`，并输出 ABI 与 Context 大小。
