@echo off
title [Windows 10 Hardening - FINAL]
color 1F
setlocal EnableDelayedExpansion
chcp 65001 >nul

:INTRO
cls
echo ================================================================
echo         WINDOWS 10 HARDENING SCRIPT - SECURE YOUR DEVICE
echo ================================================================
echo.
echo This script will apply the following security settings:
echo.
echo   [1] Disable USB mass storage access
echo   [2] Block all removable storage devices
echo   [3] Enforce driver signature check
echo   [4] Disable Bluetooth support service
echo   [5] Disable Wi-Fi auto connect (Wi-Fi Sense)
echo   [6] Enable device install event logging
echo.
set /p userchoice=Do you want to continue? (Y/N): 
if /i "!userchoice!"=="Y" goto :HARDEN
if /i "!userchoice!"=="N" goto :EXIT
echo Invalid choice. Please type Y or N.
pause
goto :INTRO

:HARDEN
echo.
echo =================== APPLYING SETTINGS ====================
echo [1] Disabling USB storage...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f >nul

echo [2] Blocking removable storage...
reg add "HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices" /v Deny_All /t REG_DWORD /d 1 /f >nul

echo [3] Enforcing driver signature check...
bcdedit /set nointegritychecks off >nul 2>&1
bcdedit /set testsigning off >nul 2>&1

echo [4] Disabling Bluetooth service...
sc config bthserv start= disabled >nul
net stop bthserv >nul 2>&1

echo [5] Disabling Wi-Fi AutoConnect...
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f >nul

echo [6] Enabling device install logging...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f >nul
wevtutil sl Microsoft-Windows-UserPnp/DeviceInstall /e:true >nul

:: ======================= STATUS CHECK =======================
echo.
echo ==================== STATUS CHECK ====================

:: USB
reg query "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start | find /i "0x4" >nul
if %errorlevel%==0 (
    echo [OK] USB storage is disabled
) else (
    echo [NOT OK] USB storage is still enabled
)

:: Removable Storage
reg query "HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices" /v Deny_All | find /i "0x1" >nul
if %errorlevel%==0 (
    echo [OK] Removable storage is blocked
) else (
    echo [NOT OK] Removable storage is not blocked
)

:: Driver Signature
bcdedit | find /i "nointegritychecks" | find /i "No" >nul
if %errorlevel%==0 (
    bcdedit | find /i "testsigning" | find /i "No" >nul
    if %errorlevel%==0 (
        echo [OK] Driver signature enforcement is ON
    ) else (
        echo [NOT OK] Test signing mode is still ON
    )
) else (
    echo [NOT OK] Driver integrity checks still OFF
)

:: Bluetooth
sc qc bthserv | find /i "DISABLED" >nul
if %errorlevel%==0 (
    echo [OK] Bluetooth service is disabled
) else (
    echo [NOT OK] Bluetooth service is still active
)

:: Wi-Fi AutoConnect
reg query "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM | find /i "0x0" >nul
if %errorlevel%==0 (
    echo [OK] Wi-Fi AutoConnect is disabled
) else (
    echo [NOT OK] Wi-Fi AutoConnect is still enabled
)

:: Event Logging
wevtutil gl Microsoft-Windows-UserPnp/DeviceInstall | find "enabled: true" >nul
if %errorlevel%==0 (
    echo [OK] Device install event logging is enabled
) else (
    echo [NOT OK] Device install event logging is not enabled
)

:: ======================= DONE =======================
echo.
echo --------------------------------------------------------
echo [*] Settings marked [OK] are applied successfully.
echo [*] Items marked [NOT OK] may need admin rights or restart.
echo --------------------------------------------------------
echo.
echo Please RESTART your system to apply all settings fully.
pause
goto :EOF

:EXIT
echo Exiting without making changes.
pause
exit
