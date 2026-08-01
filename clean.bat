@echo off
setlocal
if "%NDK_ROOT%"=="" if not "%ANDROID_NDK_ROOT%"=="" set "NDK_ROOT=%ANDROID_NDK_ROOT%"
if "%NDK_ROOT%"=="" (
    echo Set NDK_ROOT or ANDROID_NDK_ROOT to Android NDK 26.3.11579264.
    exit /b 1
)
pushd "%~dp0"
call "%NDK_ROOT%\ndk-build.cmd" clean
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
