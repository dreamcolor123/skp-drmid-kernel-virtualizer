# SKP DRM ID Kernel Virtualizer

面向 SKRoot Pro 的 Android 14+ / ARM64 纯内核 DRM ID 虚拟化模块。

当前稳定版：**1.1.0**

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

- 版本：1.1.0
- Kernel Context ABI：15 / 97,704 bytes
- Control IPC：v2
- TargetConfig：v2
- Linux 6.6.89 backend：`classic_binder-6.6`
- Linux 6.6 prologue：`d503233f d10343ff a9077bfd a9086ffc`

作者：斓梦语
