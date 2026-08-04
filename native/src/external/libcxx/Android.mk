LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := libcxx
LOCAL_SRC_FILES := abi.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CPPFLAGS := \
    -std=c++2c \
    -fno-exceptions -fno-rtti \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections \
    -D_LIBCPP_NO_EXCEPTIONS \
    -D_LIBCPP_NO_RTTI \
    -D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS \
    -D__STDC_FORMAT_MACROS

LOCAL_EXPORT_C_INCLUDES := $(LOCAL_C_INCLUDES)
LOCAL_EXPORT_CFLAGS := -fno-exceptions -fno-rtti
LOCAL_EXPORT_CPPFLAGS := -fno-exceptions -fno-rtti

include $(BUILD_STATIC_LIBRARY)
