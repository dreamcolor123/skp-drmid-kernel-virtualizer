# Changelog

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
