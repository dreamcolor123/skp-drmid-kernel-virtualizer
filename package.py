#!/usr/bin/env python3
"""Build the reproducible SKRoot Pro 1.4.0 Binder-global archive."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parent
SO = ROOT / "libs" / "arm64-v8a" / "libmodule_drmid_kernel_virtualizer.so"
DAEMON = ROOT / "libs" / "arm64-v8a" / "drmid_probe_runner"
WEBROOT = ROOT / "webroot"
DIST = ROOT / "dist"
VERSION = "1.4.0"
DISPLAY_NAME = "虚拟化DRM ID"
AUTHOR = "斓梦语"
ZIP = DIST / f"module_drmid_kernel_virtualizer-{VERSION}-arm64-run-once.zip"
SDK_VERSION = "4.6.1"
SDK_UPSTREAM_COMMIT = "68020a4e265dcfaa875e97f54f14f07422b9f1d2"
SDK_UPSTREAM = ROOT / "third_party" / "SKRoot-linuxKernelRoot"
SDK_STATIC = (
    SDK_UPSTREAM / "Pro(众测开放中)" / "src" / "testModule" /
    "kernel_module_kit" / "lib" / "libkernel_module_kit_static.a"
)
EXPECTED_SDK_SHA256 = "5b304a9d7e1c2d5d8aa2e7d2a95710d37b1f261e1a92ffe640737d747ed93f91"
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


def verify_sdk_commit() -> None:
    if not SDK_UPSTREAM.is_dir():
        raise SystemExit(
            "SKRoot SDK submodule missing: run git submodule update "
            "--init --depth 1"
        )
    try:
        actual = subprocess.run(
            ["git", "-C", str(SDK_UPSTREAM), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"cannot inspect pinned SKRoot SDK submodule: {exc}")
    if actual != SDK_UPSTREAM_COMMIT:
        raise SystemExit(
            f"SKRoot SDK commit mismatch: expected={SDK_UPSTREAM_COMMIT} "
            f"actual={actual}"
        )


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

    verify_sdk_commit()
    if not SDK_STATIC.is_file():
        raise SystemExit(
            f"SDK submodule missing: {SDK_STATIC}; run "
            "git submodule update --init --depth 1"
        )
    actual_sdk = sha256_file(SDK_STATIC)
    if actual_sdk != EXPECTED_SDK_SHA256:
        raise SystemExit(
            f"SDK {SDK_VERSION} baseline mismatch: expected={EXPECTED_SDK_SHA256} "
            f"actual={actual_sdk}"
        )

    for retired in (
        "app_catalog.cpp",
        "app_catalog.h",
        "target_config.cpp",
        "target_config.h",
        "build_label_helper.py",
        "tee_hook_builder.cpp",
        "tee_hook_builder.h",
        "tee_firmware_identity.cpp",
        "tee_firmware_identity.h",
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
    context = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
    hook_header = (ROOT / "binder_hook_builder.h").read_text(encoding="utf-8")
    require_markers(
        "HAL Binder backend",
        hook + context + hook_header,
        (
            "kCounterContextAbi = 20",
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
    reject_markers(
        "retired TEE backend",
        hook + context + hook_header + module_source,
        (
            "si_object_do_invoke",
            "free_si_object",
            "TeeFirmwareIdentity",
            "tee_backend_state",
            "tee_op9_candidates",
            "DRMID_WIDEVINE_FIRMWARE_PATH",
            "hal-binder+widevine-smcinvoke-global",
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
    executable_hook = re.sub(r"/\*.*?\*/", "", hook, flags=re.DOTALL)
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
            "window.addEventListener('blur'",
            "document.addEventListener('freeze'",
            "hidden-during-open",
            "后台已退出，请重新从管理器打开",
            "classList.add('session-ended')",
            "此页面不会自动重新连接",
            "stopArmedUntil",
            "再次点击确认停止",
            "5 秒内再次点击确认停止",
            "DRM ID虚拟化",
            "当前状态：已开启",
            "当前状态：已关闭",
            "HAL 出站 Binder（全局）",
            "binder_driver_backend",
            "binder_resolution_source",
            "binder_capabilities",
            "binder_entry_fingerprint",
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
            '"drmid_control_v5.sock"',
            '"drmid_binder_capability_v1.bin"',
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
        "Binder capability resolver",
        resolver + resolver_header + module_source,
        (
            "BinderBackend::kClassic",
            "BinderBackend::kRust",
            "kRequiredBinderCapabilities",
            "is_supported_linux_6_1_or_newer",
            "classify_semantic_entry",
            "classify_single_instruction_hook_site",
            "classify_hookable_entry",
            "branch_index == 0",
            "!address_in_core_text(target)",
            "kBinderEntryProbeBytes = 256",
            "binder_fops",
            "binder_ioctl",
            "kCapabilitySymbolCrossValidated",
            "kCapabilityHookRelocatablePrefix",
        ),
    )
    reject_markers(
        "retired kernel-version profile gate",
        resolver + module_source,
        (
            "kClassicBinder66",
            "kClassicBinder612",
            "kRustBinder612",
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
            b"hal-outbound-binder-global",
            b"drmid_control_v5.sock",
        ):
            if expected not in data:
                raise SystemExit(f"binary marker missing from {payload}: {expected!r}")
        for forbidden in (
            b"env-install",
            b"DRMID_ROOT_CMD",
            b"DRMID_EXPORT_EXPECTED",
            b"si_object_do_invoke",
            b"free_si_object",
            b"widevine.mbn",
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
