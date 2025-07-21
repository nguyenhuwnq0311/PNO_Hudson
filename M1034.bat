@echo off
title [Windows 10 Hardening - FINAL+]
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
echo   [1] Disable USB mass storage (service + storage policy)
echo   [2] Block all removable storage (read/write access)
echo   [3] Enforce driver signature + disable test mode
echo   [4] Disable Bluetooth service + deny install driver
echo   [5] Disable Wi-Fi Sense AutoConnect
echo   [6] Enable hardware install logging (DeviceInstall)
echo.
set /p userchoice=Do you want to continue? (Y/N): 
if /i "!userchoice!"=="Y" goto :HARDEN
if /i "!userchoice!"=="N" goto :EXIT
echo Invalid choice. Please type Y or N.
pause
goto :INTRO

:HARDEN
cls
echo =================== APPLYING SETTINGS ====================

:: [1] USB Mass Storage - Disable Service + Block Write
echo [1] Disabling USBSTOR service + Deny USB...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" /v WriteProtect /t REG_DWORD /d 1 /f >nul

:: [2] Deny Removable Storage via Policy
echo [2] Blocking removable storage via Group Policy...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /v Deny_All /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f >nul

:: [3] Driver Signature Enforcement
echo [3] Enforcing signed driver only...
bcdedit /set nointegritychecks off >nul
bcdedit /set testsigning off >nul

:: [4] Disable Bluetooth - Service + Driver Block
echo [4] Disabling Bluetooth services + block pairing...
sc config bthserv start= disabled >nul
net stop bthserv >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT" /v Start /t REG_DWORD /d 4 /f >nul

:: [5] Wi-Fi Sense AutoConnect Off
echo [5] Disabling Wi-Fi Sense AutoConnect...
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f >nul

:: [6] Enable Device Install Logging
echo [6] Enabling Device Install logging (event viewer)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f >nul
wevtutil sl Microsoft-Windows-UserPnp/DeviceInstall /e:true >nul

:: =================== STATUS SUMMARY ====================
echo.
echo ==================== STATUS CHECK ====================

reg query "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start | find "0x4" >nul
if %errorlevel%==0 (echo [OK] USBSTOR service is disabled) else (echo [NOT OK] USBSTOR service is enabled)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" /v WriteProtect | find "0x1" >nul
if %errorlevel%==0 (echo [OK] USB write access is blocked) else (echo [NOT OK] USB write access not blocked)

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" /v Deny_All | find "0x1" >nul
if %errorlevel%==0 (echo [OK] Removable storage is denied) else (echo [NOT OK] Removable storage not denied)

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun | find "0xff" >nul
if %errorlevel%==0 (echo [OK] AutoPlay is disabled) else (echo [NOT OK] AutoPlay still enabled)

bcdedit | find /i "nointegritychecks" | find "No" >nul && bcdedit | find /i "testsigning" | find "No" >nul
if %errorlevel%==0 (echo [OK] Driver signature enforcement is ON) else (echo [NOT OK] Test mode or integrity bypass still ON)

sc qc bthserv | find "DISABLED" >nul
if %errorlevel%==0 (echo [OK] Bluetooth service is disabled) else (echo [NOT OK] Bluetooth service still active)

reg query "HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT" /v Start | find "0x4" >nul
if %errorlevel%==0 (echo [OK] Bluetooth pairing stack is disabled) else (echo [NOT OK] Bluetooth driver still allowed)

reg query "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM | find "0x0" >nul
if %errorlevel%==0 (echo [OK] Wi-Fi AutoConnect is disabled) else (echo [NOT OK] Wi-Fi AutoConnect still enabled)

wevtutil gl Microsoft-Windows-UserPnp/DeviceInstall | find "enabled: true" >nul
if %errorlevel%==0 (echo [OK] Device install logging is enabled) else (echo [NOT OK] Device install logging not enabled)

echo.
echo --------------------------------------------------------
echo [*] Hardening complete.
echo [*] Settings marked [NOT OK] may need admin rights or manual recheck.
echo --------------------------------------------------------

:: =================== RESTART REQUIRED ====================
echo.
choice /c YN /n /m "Restart now to apply changes? (Y/N): "
if errorlevel 2 goto :EXIT
if errorlevel 1 (
    shutdown /r /t 0 /f
)
exit

:EXIT
echo Exiting without changes.
pause
exit
