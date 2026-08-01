LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_module_kit_static_prebuilt
LOCAL_SRC_FILES := ../../kernel_module_kit/lib/libkernel_module_kit_static.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := module_drmid_kernel_virtualizer
LOCAL_SRC_FILES := \
    ../module_main.cpp \
    ../web_ui.cpp \
    ../app_catalog.cpp \
    ../startup_readiness.cpp \
    ../target_config.cpp \
    ../runtime_control.cpp \
    ../runtime_profile.cpp \
    ../device_id_fingerprint.cpp \
    ../file_lifecycle.cpp \
    ../control_ipc.cpp \
    ../binder_ioctl_resolver.cpp \
    ../binder_hook_builder.cpp
KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
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
    ../startup_readiness.cpp \
    ../target_config.cpp \
    ../runtime_control.cpp \
    ../runtime_profile.cpp \
    ../device_id_fingerprint.cpp \
    ../file_lifecycle.cpp \
    ../control_ipc.cpp \
    ../binder_ioctl_resolver.cpp \
    ../binder_hook_builder.cpp
KERNEL_MODULE_KIT := $(LOCAL_PATH)/../../kernel_module_kit
LOCAL_C_INCLUDES += $(KERNEL_MODULE_KIT)/include
LOCAL_STATIC_LIBRARIES := kernel_module_kit_static_prebuilt
LOCAL_LDLIBS += -landroid -lmediandk -lz
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_EXECUTABLE)
