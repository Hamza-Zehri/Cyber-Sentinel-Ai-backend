@echo off
REM Cyber Sentinel AI - Desktop App Builder
REM Run this from the backend directory to build the standalone .exe
REM
REM Prerequisites:
REM   1. Python 3.11+ installed
REM   2. pip install pyinstaller
REM   3. Node.js 18+ installed (for frontend build)
REM   4. Inno Setup 6+ (optional, for installer)

setlocal enabledelayedexpansion

echo === Cyber Sentinel AI Desktop Builder ===
echo.

REM ---- Step 1: Build frontend ----
echo [1/5] Building frontend...
cd /d "%~dp0..\frontend"
call npm run build
if %ERRORLEVEL% neq 0 (
    echo ERROR: Frontend build failed!
    exit /b 1
)
echo Frontend built OK.
echo.

REM ---- Step 2: Copy frontend dist to backend ----
echo [2/5] Copying frontend to backend...
xcopy /E /I /Y dist "%~dp0frontend\dist"
echo Copy done.
echo.

REM ---- Step 3: Install Python dependencies ----
echo [3/5] Installing Python dependencies...
cd /d "%~dp0"
pip install -r requirements.txt
pip install pyinstaller
echo Dependencies installed.
echo.

REM ---- Step 4: Build with PyInstaller ----
echo [4/5] Building standalone executable (this may take 5-10 minutes)...
cd /d "%~dp0"
pyinstaller cyber-sentinel.spec --noconfirm --log-level WARN
if %ERRORLEVEL% neq 0 (
    echo ERROR: PyInstaller build failed!
    exit /b 1
)
echo.
echo Executable built: dist\CyberSentinel\CyberSentinel.exe

REM ---- Step 5: Build installer (optional) ----
echo [5/5] Checking for Inno Setup...
where iscc >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo Building installer with Inno Setup...
    iscc installer.iss
    echo Installer built: dist\installer\CyberSentinelAI-Setup.exe
) else (
    echo Inno Setup not found. Skipping installer build.
    echo To build the installer, install Inno Setup from: https://jrsoftware.org/isdl.php
)

echo.
echo === Build complete! ===
echo.
echo The executable is at: dist\CyberSentinel\CyberSentinel.exe
echo Run it as Administrator to enable packet capture.
pause
