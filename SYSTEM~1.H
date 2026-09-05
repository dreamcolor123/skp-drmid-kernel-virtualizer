#pragma once

// Platform AIDL NDK libraries use the system libc++ ABI namespace (__1),
// while standalone NDK applications default to __ndk1. Include libc++'s
// configuration first, then select the platform namespace before any C++
// standard-library declaration is parsed by the direct-HAL probe.
#include <__config>
#undef _LIBCPP_ABI_NAMESPACE
#define _LIBCPP_ABI_NAMESPACE __1
