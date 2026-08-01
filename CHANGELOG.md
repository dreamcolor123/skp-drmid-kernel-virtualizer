# Changelog

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
