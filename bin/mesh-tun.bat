@echo off
rem p2p virtual NIC launcher (auto request admin).
rem usage: mesh-tun.bat --server IP:8080 --room ROOM
setlocal

if "%~1"=="" (
    echo ====================================================
    echo   Usage: mesh-tun.bat --server IP:8080 --room ROOM
    echo   Ex:    mesh-tun.bat --server 175.178.155.56:8080 --room demo
    echo ====================================================
    pause
    exit /b 2
)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/k ""%~dp0p2p-client.exe mesh --tun %*""' -Verb RunAs"
    exit /b
)

"%~dp0p2p-client.exe" mesh --tun %*
