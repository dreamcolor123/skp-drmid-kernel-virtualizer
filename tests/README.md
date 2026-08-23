# SKP DRM ID Kernel Virtualizer

## 当前候选

`1.3.0-rc2` 同时使用 Widevine HAL 出站 Binder 与 SMCInvoke TEE 直连纯内核
Hook，并完整移除应用包名、应用 UID/EUID、多应用列表和应用标签 helper。所有
已识别 Widevine 通路共享当前同一个虚拟 ID，不按调用者划定作用域。

当前候选将 WebUI 操作收敛为一个“DRM ID虚拟化”开关，以及“固定值、
随机值、自定义”三种 ID 来源。未选择 ID 来源时只切换运行模式并保持当前 ID；
显式选择来源后才更新 ID，应用完成后清空临时来源选择。

支持范围：

- Android 14+；
- ARM64、64 位 Binder；
- Linux 6.12 优先；
- Linux 6.6 使用既有严格 resolver profile；
- SKP SDK 4.6.0，通过官方上游 submodule 固定到提交
  `843b8ab32905e653d5959683cfca328883e9076c`。

## 数据路径

```text
Widevine HAL 收到 BR_TRANSACTION
  -> 精确匹配 IDrmPlugin / transaction code 11 / deviceUniqueId
  -> 当前 Binder 线程 Pending 栈记录请求和 HAL identity generation
  -> HAL 发送 BC_REPLY 或 BC_REPLY_SG
  -> 原始 binder_ioctl 前弹出并关联 Pending
  -> 校验 status=0、length=32、Parcel边界和活动配置
  -> Dry-run只计数；Write对HAL自己的出站Parcel执行32字节等长覆盖
```

非 HAL TGID 在首个计数器、栈分配和用户内存复制之前直接执行原始
`binder_ioctl`。后端不再使用应用侧 Binder 接收页、page-pin、线性映射换算或
插件句柄表。

TEE 直连路径：

```text
liboemcrypto/OEMCrypto GetDeviceID
  -> si_object_do_invoke（全局导出符号）
  -> Widevine TA operation 9 / [OB] / 32 bytes
  -> Dry-run只计数；Write在返回调用方前执行32字节等长覆盖
```

TEE 后端不读取 UID、EUID、包名、TGID 或 credential。为避免误改其他 Trusted
App 的同形 `op9`，内核通过 Widevine MBN 的大小与 32 字节首尾身份建立
loader→controller→TA 对象链；已缓存 loader 时使用实机确认的
`op16→op0→op19→op20→op9` 连续签名。对象表固定为 controller 16 项、TA 32
项、fallback 16 项，采用有界 CAS，不在热路径动态分配或输出日志；
`free_si_object` 会清除旧地址，避免对象地址复用。

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

## 配置和迁移

- Kernel Context ABI：19；
- Runtime control：`DRMCTL18` / v3 / 128 字节；
- Control IPC：`DRMIPC19` / v4 / 352 字节；
- RuntimeConfigSlot：96 字节，仅保存 generation、seed、fingerprint、mode和ID；
- ID 长度固定为已验证的 32 字节；
- 派生域固定为 `global-widevine-v1`；
- v2→v3 迁移保留当前 ID 字节、mode、generation、seed generation和fingerprint，
  丢弃旧 target 字段；
- v3验证成功后，以普通文件 + `AT_SYMLINK_NOFOLLOW` 约束收敛旧 target config、
  runtime v1/v2和label helper。

WebUI 使用“DRM ID虚拟化”单一开关，并在小字中显示“当前状态：已开启/已关闭”，提供固定值、随机值、自定义三种
ID 来源和 HAL 诊断。未选择 ID 来源时，APPLY 内部使用 keep，仅调整运行模式；
显式选择来源时分别映射 derive、random、custom。页面隐藏、失焦、冻结、关闭或
心跳失效后，会话和 WebUI 监听端口自动结束；当前页面随即进入不可恢复的整页
“后台已退出，请重新从管理器打开”状态，不在页面恢复前台时自动重连。

## 构建与离线验收

```bash
git submodule update --init --depth 1
```

```bash
/mnt/c/Windows/System32/cmd.exe /d /c clean.bat
/mnt/c/Windows/System32/cmd.exe /d /c build.bat
python3 -m unittest discover -s tests -v
python3 package.py
```

发布守卫固定校验 SDK 4.6.0 静态库 SHA-256：

```text
5b304a9d7e1c2d5d8aa2e7d2a95710d37b1f261e1a92ffe640737d747ed93f91
```

当前公开仓库 clean build：`PASS`；离线回归：`153 PASS + 1 个设备采集 Fixture
按预期 SKIP`；连续两次打包哈希一致。覆盖项包括：

- HAL method/interface/property 精确关联；
- BC/BR stream边界与32字节回复改写；
- Pending并发、LIFO、锁竞争和HAL generation失效；
- HAL身份交叉核验、pidfd退出、空集发布、退避和兼容监控；
- Runtime v3布局、CRC、v2迁移保ID和双槽一致性；
- WebUI全局状态、JavaScript语法和退后台关端口竞态；
- 文件生命周期、SDK 4.6.0 上游链接与哈希、ZIP成员白名单和可复现打包；
- Linux 6.6/6.12 resolver profile回归。
- Widevine MBN普通文件、symlink、短文件、缺失和路径优先级；
- qms同形op9隔离、loader/controller/TA链、cached-loader连续签名；
- 对象free/地址复用、0/1/16/17/32/33边界、31/32/33字节；
- TEE双Hook逆序回滚、ARM64 x18禁用、固定上限与调用者过滤缺失守卫。

候选包：

```text
dist/module_drmid_kernel_virtualizer-1.3.0-rc2-arm64-run-once.zip
```

当前 SDK 4.6.0 clean build 候选 SHA-256：

```text
2690f4ff3e9965041b77e24d66cd29eec85e49294dfa9253b6ca0efc75c28fb3
```

ZIP 固定只包含：

```text
libmodule_drmid_kernel_virtualizer.so
webroot/drmid_daemon
webroot/index.html
```

## 真机阶段

首轮在 Linux 6.12 设备保持 Dry-run：确认 HAL identity、TEE firmware、
controller/TA对象、Binder reply 与TEE op9候选均正常且零写入，再显式切换 Write。
之后分别用 MediaDrm 与 OEMCrypto 直连确认共享同一fingerprint，并验证对象释放、
HAL重启、WebUI端口收口和压力稳定性。TEE 双Hook当前只在已验证的6.12函数
profile上启用；Linux 6.6继续使用Binder全局后端。

开发和测试继续遵守工作区 `AGENTS.md`：不更新/安装/卸载SKP环境，不修补或刷写
boot，不读取或输出管理器Key。
