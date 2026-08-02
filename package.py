#!/usr/bin/env python3
"""Create the flat SKRoot Pro module ZIP used by the run-once installer."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import zipfile

from build_label_helper import build as build_label_helper


ROOT = Path(__file__).resolve().parent
SO = ROOT / "libs" / "arm64-v8a" / "libmodule_drmid_kernel_virtualizer.so"
WEBROOT = ROOT / "webroot"
DAEMON = ROOT / "libs" / "arm64-v8a" / "drmid_probe_runner"
LABEL_HELPER = ROOT / "label_helper" / "drmid_label_helper.jar"
DIST = ROOT / "dist"
VERSION = "1.1.3-rc2"
DISPLAY_NAME = "虚拟化DRM ID"
AUTHOR = "斓梦语"
ZIP = DIST / f"module_drmid_kernel_virtualizer-{VERSION}-arm64-run-once.zip"
SDK_STATIC = ROOT.parent / "kernel_module_kit" / "lib" / "libkernel_module_kit_static.a"
EXPECTED_SDK_SHA256 = "9144ddc36c7ebe2bd524bc38d279c82c14d0f162cc195fcbe98f19882eab71d2"
EXPECTED_LEGACY_DEVELOPMENT_PAYLOADS = (
    "drmid-0.9.0-rc10.zip",
    "drmid-0.9.0-rc12.zip",
    "drmid_aidl_probe",
    "drmid_probe_runner",
    "drmid_rc13.zip",
    "drmid_rc13_runner",
    "drmid_rc14.zip",
    "drmid_rc14_runner",
)
NATIVECHECK_NONINTERFERENCE_MARKERS = (
    b"persist.sys.spoof",
    b"persist.sys.pihooks",
    b"persist.sys.pixelprops",
    b"libauditpatch.so",
    b"logd plt hook success",
    b"u:r:priv_app:s0:c512,c768",
    b"__system_property_set",
    b"logcat -b events",
    b"auditd:I",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_release_inputs() -> None:
    """Fail closed when version, SDK, or runner hardening drifts."""
    module_source = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
    version_match = re.search(r'SKROOT_MODULE_VERSION\("([^"]+)"\)', module_source)
    name_match = re.search(r'SKROOT_MODULE_NAME\("([^"]+)"\)', module_source)
    author_match = re.search(r'SKROOT_MODULE_AUTHOR\("([^"]+)"\)', module_source)
    if version_match is None or version_match.group(1) != VERSION:
        actual = version_match.group(1) if version_match is not None else "missing"
        raise SystemExit(
            f"module/package version mismatch: module={actual} package={VERSION}"
        )
    if name_match is None or name_match.group(1) != DISPLAY_NAME:
        actual = name_match.group(1) if name_match is not None else "missing"
        raise SystemExit(
            f"module display name mismatch: module={actual} package={DISPLAY_NAME}"
        )
    if author_match is None or author_match.group(1) != AUTHOR:
        actual = author_match.group(1) if author_match is not None else "missing"
        raise SystemExit(
            f"module author mismatch: module={actual} package={AUTHOR}"
        )

    if not SDK_STATIC.is_file():
        raise SystemExit(f"SDK static library missing: {SDK_STATIC}")
    sdk_digest = sha256_file(SDK_STATIC)
    if sdk_digest != EXPECTED_SDK_SHA256:
        raise SystemExit(
            "SDK baseline mismatch: "
            f"expected={EXPECTED_SDK_SHA256} actual={sdk_digest}"
        )

    runner_source = (ROOT / "runner_main.cpp").read_text(encoding="utf-8")
    forbidden_markers = (
        "install_skroot_environment",
        "uninstall_skroot_environment",
        'action_name == "env-install"',
        'std::getenv("DRMID_ROOT_CMD")',
    )
    present = [marker for marker in forbidden_markers if marker in runner_source]
    if present:
        raise SystemExit("runner hardening check failed: " + ", ".join(present))

    production_source = "\n".join(
        path.read_text(encoding="utf-8")
        for pattern in ("*.cpp", "*.h")
        for path in sorted(ROOT.glob(pattern))
    )
    forbidden_production_markers = (
        "DRMID_EXPORT_EXPECTED",
        "DRMID_EXPORT_EXPECTED_READABLE",
        "export_expected_profile",
        "fchmod(fd, 0644)",
    )
    present = [
        marker for marker in forbidden_production_markers if marker in production_source
    ]
    if present:
        raise SystemExit(
            "production export hardening check failed: " + ", ".join(present)
        )

    lifecycle_source = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
    missing_payloads = [
        name
        for name in EXPECTED_LEGACY_DEVELOPMENT_PAYLOADS
        if lifecycle_source.count(f'"{name}"') != 1
    ]
    required_cleanup_primitives = (
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "AT_SYMLINK_NOFOLLOW",
        "S_ISREG",
        "unlinkat(owned_fd, entry->d_name, 0)",
        "std::strcmp(name, expected) == 0",
    )
    missing_primitives = [
        marker for marker in required_cleanup_primitives if marker not in lifecycle_source
    ]
    if missing_payloads or missing_primitives:
        raise SystemExit(
            "legacy payload cleanup hardening check failed: "
            f"payloads={missing_payloads} primitives={missing_primitives}"
        )

    startup_source = (ROOT / "startup_readiness.cpp").read_text(encoding="utf-8")
    startup_header = (ROOT / "startup_readiness.h").read_text(encoding="utf-8")
    startup_main = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
    required_startup_markers = (
        "wait_for_adaptive_startup_readiness",
        "startup_observations_quiet",
        '"init.svc.bootanim", "stopped"',
        '"init.svc.mediadrm", "running"',
        'name == "system_server"',
        'name == "surfaceflinger"',
        "uint32_t stable_ms = 3000",
        "uint32_t deadline_ms = 45000",
    )
    startup_text = startup_source + startup_header + startup_main
    missing_startup = [
        marker for marker in required_startup_markers if marker not in startup_text
    ]
    forbidden_fixed_delay = (
        "kDefaultPostBootDelayMs",
        "DRMID_POST_BOOT_DELAY_MS",
        "post-boot settle delay",
    )
    present_fixed_delay = [
        marker for marker in forbidden_fixed_delay if marker in startup_main
    ]
    if missing_startup or present_fixed_delay:
        raise SystemExit(
            "adaptive startup guard failed: "
            f"missing={missing_startup} fixed_delay={present_fixed_delay}"
        )

    target_source = (ROOT / "target_config.cpp").read_text(encoding="utf-8")
    webui_source = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
    webui_html = (WEBROOT / "index.html").read_text(encoding="utf-8")
    if f">{VERSION} · {AUTHOR}</p>" not in webui_html:
        raise SystemExit("WebUI release version does not match package version")
    required_stop_flow = (
        "stopArmedUntil",
        "再次点击确认停止",
        "5 秒内再次点击确认停止",
    )
    missing_stop_flow = [
        marker for marker in required_stop_flow if marker not in webui_html
    ]
    if missing_stop_flow or "confirm(" in webui_html:
        raise SystemExit(
            "WebUI foreground-safe STOP guard failed: "
            f"missing={missing_stop_flow} native_confirm={'confirm(' in webui_html}"
        )
    required_bootstrap = (
        "fresh installation has no device-independent package name",
        "desired.rule_mode = static_cast<uint32_t>(TargetRuleMode::kAll)",
        "unconfigured bootstrap: no target package",
        "Dry-run is mandatory until a package resolves",
        '\\\"configured\\\"',
        '"packages-empty"',
        "等待选择应用",
        "请从设备选择应用，或输入包名",
        "选择应用，一次启用",
        "启用并应用",
        "操作期间请保持页面在前台",
        "设备原ID指纹",
        "虚拟ID指纹",
        "s.configured===false?'derive':'keep'",
    )
    bootstrap_text = target_source + startup_main + webui_source + webui_html
    missing_bootstrap = [
        marker for marker in required_bootstrap if marker not in bootstrap_text
    ]
    forbidden_bootstrap = []
    if "kDefaultPackage" in target_source or "kDefaultPackage" in webui_source:
        forbidden_bootstrap.append("kDefaultPackage")
    if ">com.sf.activity</textarea>" in webui_html:
        forbidden_bootstrap.append("pre-filled-com.sf.activity")
    if missing_bootstrap or forbidden_bootstrap:
        raise SystemExit(
            "first-start bootstrap guard failed: "
            f"missing={missing_bootstrap} forbidden={forbidden_bootstrap}"
        )

    hook_lock_source = (ROOT / "binder_hook_builder.cpp").read_text(
        encoding="utf-8"
    )
    context_source = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
    # x18 is the ARM64 platform register and is the shadow-call-stack pointer
    # on the target kernel. Strip comments so the root-cause note itself does
    # not trip the guard, then reject every executable emitter reference rather
    # than only the exact spelling used by the former ticket lock.
    hook_lock_executable_source = re.sub(
        r"/\*.*?\*/", "", hook_lock_source, flags=re.DOTALL
    )
    hook_lock_executable_source = re.sub(
        r"//.*", "", hook_lock_executable_source
    )
    platform_register_uses = sorted(
        set(re.findall(r"\b[wx]18\b", hook_lock_executable_source))
    )
    required_hook_lock = (
        "CONFIG_SHADOW_CALL_STACK",
        "kMapLockTryCount = 8",
        "emit_bounded_lock_acquire",
        "a->ldaxr(x12, ptr(x9))",
        "a->stxr(w13, x10, ptr(x9))",
        "a->clrex(15)",
        "pending_lock_state",
        "pending_lock_drops",
        "plugin_lock_state",
        "plugin_lock_drops",
        "kCounterContextAbi = 17",
        "kPendingBucketWays = 8",
        "kPendingBucketWayShift = 3",
        "task_struct address can be reused",
        "Reclaim the oldest entry in the bounded bucket",
        "kPluginBucketWays = 8",
        "kPluginBucketWayShift = 3",
        "least-recently-used occupied slot",
        "recovered collision/eviction events",
        "emit_package_uid_or_target_gate",
        "kAndroidAppUidStart = 10000",
        "aarch64_asm_mov_w(a, w12, kAndroidAppUidStart)",
        "without touching counters",
        "static_cast<uint32_t>(getpid())",
        "app_uid_check",
    )
    hook_lock_text = hook_lock_source + context_source
    missing_hook_lock = [
        marker for marker in required_hook_lock if marker not in hook_lock_text
    ]
    forbidden_hook_lock = (
        "emit_pending_lock_acquire(a, context_kaddr, x18)",
        "emit_plugin_lock_acquire(a, context_kaddr, x18)",
        "pending_lock_next",
        "pending_lock_serving",
        "plugin_lock_next",
        "plugin_lock_serving",
    )
    present_hook_lock = [
        marker for marker in forbidden_hook_lock if marker in hook_lock_text
    ]
    if missing_hook_lock or present_hook_lock or platform_register_uses:
        raise SystemExit(
            "Binder lock hardening guard failed: "
            f"missing={missing_hook_lock} forbidden={present_hook_lock} "
            f"platform_registers={platform_register_uses}"
        )

    required_reclaim_diagnostics = (
        "miss/overflow/reclaim/oneway=",
        "map insert/reuse/reclaim/active=",
        "Binder parser hook installed context=%p abi=%",
        "Binder entry gate=installer-tgid,target-euid,",
    )
    missing_reclaim_diagnostics = [
        marker for marker in required_reclaim_diagnostics
        if marker not in startup_main
    ]
    if missing_reclaim_diagnostics:
        raise SystemExit(
            "Binder map reclaim diagnostics guard failed: "
            f"missing={missing_reclaim_diagnostics}"
        )

    control_source = (ROOT / "control_ipc.cpp").read_text(encoding="utf-8")
    required_idle_power_markers = (
        "const int poll_timeout_ms = max_runtime_ms == 0 ? -1 : kPollMs",
        "poll(&descriptor, 1, poll_timeout_ms)",
    )
    missing_idle_power = [
        marker for marker in required_idle_power_markers
        if marker not in control_source
    ]
    if missing_idle_power or "poll(&descriptor, 1, kPollMs)" in control_source:
        raise SystemExit(
            "Control daemon idle-power guard failed: "
            f"missing={missing_idle_power}"
        )

    resolver_source = (ROOT / "binder_ioctl_resolver.cpp").read_text(
        encoding="utf-8"
    )
    resolver_header = (ROOT / "binder_ioctl_resolver.h").read_text(
        encoding="utf-8"
    )
    required_kernel66_profile = (
        "kClassicBinder66",
        "classic_binder-6.6",
        "0xd10343ffU",
        "0xa9077bfdU",
        "0xa9086ffcU",
        "offsets.file_f_op = 0xc0",
        "offsets.fops_unlocked_ioctl = 0x48",
        "62e54bf3e7aa39bb",
        "is_supported_ioctl_profile",
        'kernel_version.rfind("6.6.", 0)',
        'kernel_version.rfind("6.12.", 0)',
    )
    kernel66_text = resolver_source + resolver_header + startup_main
    missing_kernel66 = [
        marker for marker in required_kernel66_profile
        if marker not in kernel66_text
    ]
    forbidden_cross_family = (
        "is_supported_612_ioctl_profile",
        'kernel_version.rfind("6.12.", 0) != 0',
    )
    present_cross_family = [
        marker for marker in forbidden_cross_family
        if marker in kernel66_text
    ]
    if missing_kernel66 or present_cross_family:
        raise SystemExit(
            "Linux 6.6 strict profile guard failed: "
            f"missing={missing_kernel66} forbidden={present_cross_family}"
        )


def verify_built_payloads() -> None:
    """Reject stale binaries left from an earlier source/SDK build."""
    expected_version = VERSION.encode("ascii")
    stale_candidate_prefix = expected_version + b"-rc"
    expected_name = DISPLAY_NAME.encode("utf-8")
    expected_author = AUTHOR.encode("utf-8")
    forbidden_binary_markers = (
        b"env-install",
        b"DRMID_ROOT_CMD",
        b"DRMID_EXPORT_EXPECTED",
        b"DRMID_EXPORT_EXPECTED_READABLE",
    ) + NATIVECHECK_NONINTERFERENCE_MARKERS
    for payload in (SO, DAEMON):
        data = payload.read_bytes()
        if expected_version not in data:
            raise SystemExit(f"stale build version in {payload}: expected {VERSION}")
        if stale_candidate_prefix in data:
            raise SystemExit(
                f"stale release-candidate build in {payload}: expected {VERSION}"
            )
        if expected_name not in data or expected_author not in data:
            raise SystemExit(
                f"stale module identity in {payload}: "
                f"expected {DISPLAY_NAME} / {AUTHOR}"
            )
        present = [
            marker.decode("ascii")
            for marker in forbidden_binary_markers
            if marker in data
        ]
        if present:
            raise SystemExit(
                f"payload hardening check failed for {payload}: "
                + ", ".join(present)
            )

    if not LABEL_HELPER.is_file() or LABEL_HELPER.stat().st_size > 128 * 1024:
        raise SystemExit(f"label helper missing or oversized: {LABEL_HELPER}")
    with zipfile.ZipFile(LABEL_HELPER, "r") as helper:
        if helper.namelist() != ["classes.dex"]:
            raise SystemExit("label helper must contain only classes.dex")
        dex = helper.read("classes.dex")
    for marker in (b"DrmidAppLabels", b"getInstalledApplications", b"#locale"):
        if marker not in dex:
            raise SystemExit(f"label helper marker missing: {marker!r}")
    helper_forbidden = [
        marker.decode("ascii")
        for marker in forbidden_binary_markers
        if marker in dex
    ]
    if helper_forbidden:
        raise SystemExit(
            "label helper hardening check failed: " + ", ".join(helper_forbidden)
        )


def verify_archive_members() -> None:
    expected = {
        "drmid_label_helper.jar",
        "libmodule_drmid_kernel_virtualizer.so",
        "webroot/drmid_daemon",
        "webroot/index.html",
    }
    with zipfile.ZipFile(ZIP, "r") as archive:
        actual = set(archive.namelist())
    if actual != expected:
        raise SystemExit(
            "unexpected module ZIP members: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    if any(name.startswith("data/local/tmp/") or ".." in name for name in actual):
        raise SystemExit("public or traversing path in module ZIP")


def main() -> int:
    build_label_helper()
    verify_release_inputs()
    for required in (SO, DAEMON, LABEL_HELPER):
        if not required.is_file():
            raise SystemExit(f"build output missing: {required}")
    verify_built_payloads()
    DIST.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.write(SO, SO.name)
        archive.write(DAEMON, "webroot/drmid_daemon")
        helper_info = zipfile.ZipInfo(
            LABEL_HELPER.name, date_time=(1980, 1, 1, 0, 0, 0)
        )
        helper_info.compress_type = zipfile.ZIP_DEFLATED
        helper_info.external_attr = 0o100600 << 16
        archive.writestr(helper_info, LABEL_HELPER.read_bytes())
        for asset in sorted(path for path in WEBROOT.rglob("*") if path.is_file()):
            archive.write(asset, asset.relative_to(ROOT).as_posix())
    verify_archive_members()
    digest = sha256_file(ZIP)
    manifest = "".join(
        f"{sha256_file(package)}  {package.name}\n"
        for package in sorted(DIST.glob("*.zip"))
    )
    (DIST / "SHA256SUMS").write_text(manifest, encoding="utf-8")
    print(ZIP)
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
