@echo off
reg query HKU\S-1-5-19 >nul 2>nul || ( powershell -nop -c "start-process cmd.exe -ArgumentList '/c call \"%~f0\"' -verb runas" &exit)
cd /d "%~dp0"
@REM ���ø�����
set parentProcess="lsass"
@REM ����Ҫִ�еĳ���·��
set cmdFullPath="C:\Windows\system32\notepad.exe"
@REM ���ó���Ĳ���
set cmdArgs=" .\README.MD"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\psgetsys.ps1" %parentProcess% %cmdFullPath% %cmdArgs%
@REM pause
exit /b