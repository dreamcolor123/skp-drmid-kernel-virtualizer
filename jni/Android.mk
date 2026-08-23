LOCAL_PATH := $(call my-dir)
KERNEL_MODULE_KIT := $(LOCAL_PATH)/../.sdk-cache/kernel_module_kit

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_module_kit_static_prebuilt
LOCAL_SRC_FILES := ../.sdk-cache/kernel_module_kit/lib/libkernel_module_kit_static.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := module_drmid_kernel_virtualizer

LOCAL_SRC_FILES := \
    ../module_main.cpp \
    ../web_ui.cpp \
    ../hal_identity.cpp \
    ../startup_readiness.cpp \
    ../runtime_control.cpp \
    ../runtime_profile.cpp \
    ../device_id_fingerprint.cpp \
    ../file_lifecycle.cpp \
    ../control_ipc.cpp \
    ../binder_ioctl_resolver.cpp \
    ../binder_hook_builder.cpp \
    ../tee_firmware_identity.cpp \
    ../tee_hook_builder.cpp

LOCAL_C_INCLUDES += $(KERNEL_MODULE_KIT)/include
LOCAL_STATIC_LIBRARIES := kernel_module_kit_static_prebuilt
LOCAL_LDLIBS += -landroid -lmediandk -lz

include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := drmid_probe_runner

LOCAL_SRC_FILES := \
    ../runner_main.cpp \
    ../module_main.cpp \
    ../hal_identity.cpp \
    ../startup_readiness.cpp \
    ../runtime_control.cpp \
    ../runtime_profile.cpp \
    ../device_id_fingerprint.cpp \
    ../file_lifecycle.cpp \
    ../control_ipc.cpp \
    ../binder_ioctl_resolver.cpp \
    ../binder_hook_builder.cpp \
    ../tee_firmware_identity.cpp \
    ../tee_hook_builder.cpp

LOCAL_C_INCLUDES += $(KERNEL_MODULE_KIT)/include
LOCAL_STATIC_LIBRARIES := kernel_module_kit_static_prebuilt
LOCAL_LDLIBS += -landroid -lmediandk -lz

include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_EXECUTABLE)

# Device-only rc15 acceptance probe. It is deliberately excluded from
# package.py and exposes only fixed file-lifecycle fixture actions.
include $(CLEAR_VARS)
LOCAL_MODULE := drmid_file_lifecycle_probe
LOCAL_SRC_FILES := \
    ../tests/device_file_lifecycle_probe.cpp \
    ../control_ipc.cpp
LOCAL_C_INCLUDES += $(KERNEL_MODULE_KIT)/include $(LOCAL_PATH)/..
LOCAL_STATIC_LIBRARIES := kernel_module_kit_static_prebuilt
LOCAL_LDLIBS += -lz
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_EXECUTABLE)

# Optional device-only AIDL probe. Its extracted device libraries and generated
# AIDL bindings are intentionally not tracked; a clean public clone still builds
# the formal module and daemon without them.
DRMID_AIDL_PROBE_INPUTS := \
    $(wildcard $(LOCAL_PATH)/../prebuilt/device/libc++.so) \
    $(wildcard $(LOCAL_PATH)/../prebuilt/device/android.hardware.drm-V1-ndk.so) \
    $(wildcard $(LOCAL_PATH)/../generated/drm_aidl_v1/include/aidl/android/hardware/drm/IDrmPlugin.h)

ifeq ($(words $(DRMID_AIDL_PROBE_INPUTS)),3)
    include $(CLEAR_VARS)
    LOCAL_MODULE := system_libcxx_device_prebuilt
    LOCAL_SRC_FILES := ../prebuilt/device/libc++.so
    include $(PREBUILT_SHARED_LIBRARY)

    include $(CLEAR_VARS)
    LOCAL_MODULE := drm_v1_ndk_device_prebuilt
    LOCAL_SRC_FILES := ../prebuilt/device/android.hardware.drm-V1-ndk.so
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../generated/drm_aidl_v1/include
    include $(PREBUILT_SHARED_LIBRARY)

    include $(CLEAR_VARS)
    LOCAL_MODULE := drmid_aidl_probe
    LOCAL_SRC_FILES := ../aidl_drm_generated_probe.cpp
    LOCAL_C_INCLUDES := $(LOCAL_PATH)/../generated/drm_aidl_v1/include
    LOCAL_CPPFLAGS += -include $(LOCAL_PATH)/../system_libcpp_abi.h
    LOCAL_SHARED_LIBRARIES := \
        drm_v1_ndk_device_prebuilt \
        system_libcxx_device_prebuilt
    LOCAL_LDLIBS += -lbinder_ndk -ldl
    include $(LOCAL_PATH)/build_macros.mk
    include $(BUILD_EXECUTABLE)
endif

include $(CLEAR_VARS)
LOCAL_MODULE := drmid_media_probe
LOCAL_SRC_FILES := ../media_drm_probe.cpp
LOCAL_LDLIBS += -lmediandk
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_EXECUTABLE)
