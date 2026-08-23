#!/usr/bin/env python3
"""Build the reproducible SKRoot Pro 1.3.0-rc1 global module archive."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parent
SO = ROOT / "libs" / "arm64-v8a" / "libmodule_drmid_kernel_virtualizer.so"
DAEMON = ROOT / "libs" / "arm64-v8a" / "drmid_probe_runner"
WEBROOT = ROOT / "webroot"
DIST = ROOT / "dist"
VERSION = "1.3.0-rc1"
DISPLAY_NAME = "虚拟化DRM ID"
AUTHOR = "斓梦语"
ZIP = DIST / f"module_drmid_kernel_virtualizer-{VERSION}-arm64-run-once.zip"
SDK_STATIC = ROOT.parent / "kernel_module_kit" / "lib" / "libkernel_module_kit_static.a"
EXPECTED_SDK_SHA256 = "9144ddc36c7ebe2bd524bc38d279c82c14d0f162cc195fcbe98f19882eab71d2"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_markers(label: str, text: str, markers: tuple[str, ...]) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{label} guard missing: {missing}")


def reject_markers(label: str, text: str, markers: tuple[str, ...]) -> None:
    present = [marker for marker in markers if marker in text]
    if present:
        raise SystemExit(f"{label} guard rejected: {present}")


def verify_release_inputs() -> None:
    module_source = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
    for macro, expected in (
        ("SKROOT_MODULE_VERSION", VERSION),
        ("SKROOT_MODULE_NAME", DISPLAY_NAME),
        ("SKROOT_MODULE_AUTHOR", AUTHOR),
    ):
        match = re.search(rf'{macro}\("([^"]+)"\)', module_source)
        actual = match.group(1) if match else "missing"
        if actual != expected:
            raise SystemExit(f"{macro} mismatch: expected={expected} actual={actual}")

    if not SDK_STATIC.is_file():
        raise SystemExit(f"SDK static library missing: {SDK_STATIC}")
    actual_sdk = sha256_file(SDK_STATIC)
    if actual_sdk != EXPECTED_SDK_SHA256:
        raise SystemExit(
            f"SDK 4.5.4 baseline mismatch: expected={EXPECTED_SDK_SHA256} "
            f"actual={actual_sdk}"
        )

    for retired in (
        "app_catalog.cpp",
        "app_catalog.h",
        "target_config.cpp",
        "target_config.h",
        "build_label_helper.py",
    ):
        if (ROOT / retired).exists():
            raise SystemExit(f"retired multi-application source remains: {retired}")

    runner = (ROOT / "runner_main.cpp").read_text(encoding="utf-8")
    reject_markers(
        "SKP environment",
        runner,
        (
            "install_skroot_environment",
            "uninstall_skroot_environment",
            'action_name == "env-install"',
            'std::getenv("DRMID_ROOT_CMD")',
        ),
    )

    hook = (ROOT / "binder_hook_builder.cpp").read_text(encoding="utf-8")
    tee_hook = (ROOT / "tee_hook_builder.cpp").read_text(encoding="utf-8")
    tee_firmware = (ROOT / "tee_firmware_identity.cpp").read_text(encoding="utf-8")
    context = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
    hook_header = (ROOT / "binder_hook_builder.h").read_text(encoding="utf-8")
    require_markers(
        "HAL Binder backend",
        hook + context + hook_header,
        (
            "kCounterContextAbi = 19",
            "kHalIdentityLimit = 4",
            "kWidevineDeviceUniqueIdBytes = 32",
            "emit_hal_identity_gate",
            "kGetPropertyByteArrayTransactionCode = 11",
            "emit_reset_transaction_parse_scratch",
            "emit_parse_hal_correlated_reply",
            "static_cast<uint32_t>(BC_REPLY)",
            "static_cast<uint32_t>(BC_REPLY_SG)",
            "kReplyFlagHalCorrelated",
            "copy_to_user",
            "publish_hal_identities",
            "active_hal_identity_slot",
            "pending_generation_stale",
            "a->stlr(w10, ptr(x9))",
        ),
    )
    require_markers(
        "caller-global Widevine TEE backend",
        tee_hook + tee_firmware + context + module_source,
        (
            '"si_object_do_invoke"',
            '"free_si_object"',
            "kTeeControllerObjectLimit = 16",
            "kTeeWidevineObjectLimit = 32",
            "kTeeFallbackStateLimit = 16",
            "emit_fallback_consume_ready",
            "emit_table_contains",
            "a->casal",
            "copy_from_user",
            "copy_to_user",
            "O_NOFOLLOW",
            '"/vendor/firmware_mnt/image/widevine.mbn"',
            "hal-binder+widevine-smcinvoke-global",
        ),
    )
    reject_markers(
        "TEE caller filters",
        tee_hook,
        (
            "target_euids",
            "cred_euid",
            "sender_euid",
            "get_task_struct_tgid_offset",
            "get_task_struct_cred_offset",
            "emit_hal_identity_gate",
            "kmalloc",
            "kzalloc",
        ),
    )
    reject_markers(
        "retired application hot path",
        hook + context + hook_header + module_source,
        (
            "plugin_map",
            "DirectPageMapProfile",
            "replacement_page_pin",
            "replacement_access_vm",
            "emit_package_uid_or_target_gate",
            "TargetRuleMode",
            "kRuntimeTargetLimit",
            "target_euids",
            "target_count",
            "rule_mode",
            "cred_euid",
            "#if 0",
        ),
    )
    executable_hook = re.sub(r"/\*.*?\*/", "", hook + tee_hook, flags=re.DOTALL)
    executable_hook = re.sub(r"//.*", "", executable_hook)
    if re.search(r"\b[wx]18\b", executable_hook):
        raise SystemExit("ARM64 x18 shadow-call-stack register used by hook emitter")

    hal = (ROOT / "hal_identity.cpp").read_text(encoding="utf-8")
    ipc = (ROOT / "control_ipc.cpp").read_text(encoding="utf-8")
    require_markers(
        "HAL identity lifecycle",
        hal + ipc,
        (
            "pidfd_open",
            "O_NOFOLLOW",
            "hal_drm_widevine",
            "kHalRediscoveryInitialMs = 50",
            "kHalRediscoveryMaximumMs = 2000",
            "kHalProcFallbackPollMs = 5000",
            "clear_monitored_identities",
            "publish_monitored_identities",
            "descriptors.push_back({pidfd, POLLIN, 0})",
            "lifecycle_timeout_ms = -1",
            "HalMonitorBackend::kPidfd",
            "hal_identity_restarts",
        ),
    )

    runtime = (ROOT / "runtime_control.cpp").read_text(encoding="utf-8")
    runtime_header = (ROOT / "runtime_control.h").read_text(encoding="utf-8")
    profile = (ROOT / "runtime_profile.cpp").read_text(encoding="utf-8")
    require_markers(
        "global runtime",
        runtime + runtime_header + profile,
        (
            "DRMCTL18",
            "kRuntimeControlVersion = 3",
            "RuntimeControlRecordV3",
            "migrate_runtime_control_v2",
            "global-widevine-v1",
        ),
    )

    web_cpp = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
    web_html = (WEBROOT / "index.html").read_text(encoding="utf-8")
    require_markers(
        "global WebUI",
        web_cpp + web_html,
        (
            "/api/session/close",
            "visibilitychange",
            "pagehide",
            "sendBeacon",
            "hidden-during-open",
            "stopArmedUntil",
            "再次点击确认停止",
            "5 秒内再次点击确认停止",
            "DRM ID虚拟化",
            "当前状态：已开启",
            "当前状态：已关闭",
            "Binder + TEE 直连（全局）",
            f">{VERSION} · {AUTHOR}<",
        ),
    )
    reject_markers(
        "retired application WebUI",
        web_cpp + web_html,
        (
            "/api/apps",
            "selected-apps",
            "package_name",
            "packages_text",
            "选择应用",
            "confirm(",
        ),
    )

    lifecycle = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
    require_markers(
        "state convergence",
        lifecycle + module_source,
        (
            "cleanup_legacy_target_state_after_global_migration",
            '"drmid_runtime_control_v3.bin"',
            '"drmid_control_v4.sock"',
            '"drmid_label_helper.jar"',
            "AT_SYMLINK_NOFOLLOW",
            "S_ISREG",
        ),
    )

    production = "\n".join(
        path.read_text(encoding="utf-8")
        for pattern in ("*.cpp", "*.h")
        for path in sorted(ROOT.glob(pattern))
    )
    reject_markers(
        "production export",
        production,
        (
            "DRMID_EXPORT_EXPECTED",
            "DRMID_EXPORT_EXPECTED_READABLE",
            "export_expected_profile",
            "fchmod(fd, 0644)",
        ),
    )

    resolver = (ROOT / "binder_ioctl_resolver.cpp").read_text(encoding="utf-8")
    resolver_header = (ROOT / "binder_ioctl_resolver.h").read_text(encoding="utf-8")
    require_markers(
        "kernel family",
        resolver + resolver_header + module_source,
        (
            "kClassicBinder66",
            "classic_binder-6.6",
            'kernel_version.rfind("6.6.", 0)',
            'kernel_version.rfind("6.12.", 0)',
            "is_supported_ioctl_profile",
        ),
    )


def verify_built_payloads() -> None:
    required = (SO, DAEMON, WEBROOT / "index.html")
    for path in required:
        if not path.is_file():
            raise SystemExit(f"build output missing: {path}")

    source_mtime = max(
        path.stat().st_mtime_ns
        for pattern in ("*.cpp", "*.h", "jni/*.mk")
        for path in ROOT.glob(pattern)
    )
    for payload in (SO, DAEMON):
        if payload.stat().st_mtime_ns < source_mtime:
            raise SystemExit(f"stale build output: {payload}")
        data = payload.read_bytes()
        for expected in (
            VERSION.encode("ascii"),
            DISPLAY_NAME.encode("utf-8"),
            AUTHOR.encode("utf-8"),
            b"hal-binder+widevine-smcinvoke-global",
            b"drmid_control_v4.sock",
        ):
            if expected not in data:
                raise SystemExit(f"binary marker missing from {payload}: {expected!r}")
        for forbidden in (
            b"env-install",
            b"DRMID_ROOT_CMD",
            b"DRMID_EXPORT_EXPECTED",
        ):
            if forbidden in data:
                raise SystemExit(f"binary marker rejected from {payload}: {forbidden!r}")


def add_reproducible_file(
    archive: zipfile.ZipFile, source: Path, member: str, mode: int
) -> None:
    info = zipfile.ZipInfo(member, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (0o100000 | mode) << 16
    archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def build_archive() -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        add_reproducible_file(archive, SO, SO.name, 0o600)
        add_reproducible_file(archive, DAEMON, "webroot/drmid_daemon", 0o700)
        add_reproducible_file(
            archive, WEBROOT / "index.html", "webroot/index.html", 0o600
        )


def verify_archive_members() -> None:
    expected = {
        "libmodule_drmid_kernel_virtualizer.so",
        "webroot/drmid_daemon",
        "webroot/index.html",
    }
    with zipfile.ZipFile(ZIP, "r") as archive:
        names = archive.namelist()
        actual = set(names)
        if actual != expected or len(names) != len(expected):
            raise SystemExit(
                f"unexpected ZIP members: missing={sorted(expected-actual)} "
                f"extra={sorted(actual-expected)}"
            )
        if any(name.startswith("data/local/tmp/") or ".." in name for name in names):
            raise SystemExit("public or traversing path in module ZIP")
        if any("label_helper" in name for name in names):
            raise SystemExit("retired application label helper in module ZIP")


def main() -> int:
    verify_release_inputs()
    verify_built_payloads()
    build_archive()
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
