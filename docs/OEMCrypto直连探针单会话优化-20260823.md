# OEMCrypto 直连探针单会话优化

日期：2026-08-23（Asia/Shanghai）

## 问题

`1.3.0-rc1` Write 真机验收最初使用 50 个短命进程，每个进程执行一次
OEMCrypto Initialize、两次 GetDeviceID 和一次 Terminate。无间隔反复创建和销毁
进程会撞上 SMCInvoke 服务端的异步释放窗口，表现为部分新会话初始化失败。

模块计数同期满足：

```text
tee_op9_write_faults=0
tee_loader_identity_faults=0
tee_state_full=0
active controller / TA object=0 / 0
```

停止突发进程创建后，单次 OEMCrypto 调用立即恢复并继续逐字节匹配虚拟 ID。因此该
现象属于验收 Fixture 的 transport 生命周期抖动，不是 TEE Hook 写入或对象表错误。

## 实现

更新 `tools/oemcrypto_direct_probe.cpp`：

- 新增 `DRMID_REPEAT=1..1000`，默认保持两次读取；
- 每个进程只 Initialize 一次、Terminate 一次；
- 在同一会话内循环 GetDeviceID，并对所有返回值做长度、稳定性和期望值比较；
- 输出 `repeat` 和 `completed`，不输出 ID 字节或摘要；
- 每轮复用缓冲先清零，退出前再次清零 first/current/expected；
- root/0600 期望文件改为 Initialize 前读取，读取失败时不再留下已初始化但未
  Terminate 的会话。

ARM64 NDK 以 `-Wall -Wextra -Werror` 编译通过。

## 当前设备验证

设备保持 DRMID daemon 与 Hook 停止，只验证原版 OEMCrypto transport：

```text
DRMID_REPEAT=100
get1=0 get2=0
length=32
stable=yes
repeat=100 completed=100
terminate=0
elapsed=520 ms
```

同一测试前后内核日志计数：

```text
smcinvoke server_release: 226 -> 228
delta=2
```

两条释放记录对应该 OEMCrypto 进程创建的两个服务对象；100 次 GetDeviceID 没有
产生 100 轮会话销毁。相较 50 个短命进程约 100 条释放记录，会话释放事件减少约
98%，并消除了异步释放窗口中的初始化失败。

Activity、SurfaceFlinger、hlosminkdaemon 均在线；未出现 SMCInvoke fault、Oops、
panic、hung task 或锁死。

## 结论

后续 Binder 外 TEE 验收统一使用单进程 `DRMID_REPEAT=N`。只有专门验证对象释放和
地址复用时才创建多个进程，并在会话之间保留至少 200 ms 间隔。模块热路径不增加
等待、重试或 transport 特判，继续保持无阻塞和严格有界。
