@echo off
setlocal

if "%NDK_ROOT%"=="" set "NDK_ROOT=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.3.11579264"
set "NDK_BUILD=%NDK_ROOT%\ndk-build.cmd"

if not exist "%NDK_BUILD%" (
    echo NDK not found: %NDK_BUILD%
    exit /b 1
)

pushd "%~dp0"
python prepare_sdk.py
if errorlevel 1 (
    popd
    exit /b 1
)
call "%NDK_BUILD%" -j8
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
