@echo off
if not exist ProcessSentinel.exe (
    echo Please run compile.bat first.
    pause
    exit /b 1
)
ProcessSentinel.exe
