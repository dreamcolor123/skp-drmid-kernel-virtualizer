@echo off
setlocal
if "%NDK_ROOT%"=="" set "NDK_ROOT=C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.3.11579264"
pushd "%~dp0"
python prepare_sdk.py
if errorlevel 1 (
    popd
    exit /b 1
)
call "%NDK_ROOT%\ndk-build.cmd" clean
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
