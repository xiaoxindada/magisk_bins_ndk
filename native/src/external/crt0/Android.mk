LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := crt0

# -lc -lm is hardcoded in this variable, disable it
TARGET_LDLIBS :=

# Manually link the compiler runtime library
LOCAL_compiler_rt := $(shell $(TARGET_CC) -target $(LLVM_TRIPLE)$(TARGET_PLATFORM_LEVEL) --print-libgcc-file-name)

LOCAL_EXPORT_LDFLAGS := -static -nostartfiles -nodefaultlibs \
    "$(LOCAL_compiler_rt)" -Wl,-wrap,abort_message
LOCAL_CFLAGS := -Wno-c99-designator -Wno-shift-op-parentheses
LOCAL_EXPORT_CFLAGS := -DUSE_CRT0

LOCAL_SRC_FILES := \
    crtbegin.c \
    fmt.c \
    malloc.c \
    mem.c \
    misc.c \
    stdio.c \
    syscalls.c \
    printf/printf.c \
    bionic/syscall-$(TARGET_ARCH).S \
    $(wildcard $(LOCAL_PATH)/musl/*.c) \
    $(wildcard $(LOCAL_PATH)/bionic/*/*.c) \
    $(wildcard $(LOCAL_PATH)/bionic/*.cpp)

LOCAL_SRC_FILES := $(LOCAL_SRC_FILES:$(LOCAL_PATH)/%=%)

include $(BUILD_STATIC_LIBRARY)
