@echo off
echo ====================================
echo   Building ServerMon Standalone App
echo ====================================
call .\.venv\Scripts\pyinstaller.exe --noconsole --name "ServerMon" --add-data "gui.ui;." --add-data "config;config" --clean main.py
if errorlevel 1 (
    echo PyInstaller build failed!
    pause
    exit /b %errorlevel%
)

echo.
echo ====================================
echo   Compiling Windows Installer
echo ====================================
set "ISCC_PATH=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"

"%ISCC_PATH%" installer.iss
if errorlevel 1 (
    echo Inno Setup compilation failed!
    pause
    exit /b %errorlevel%
)

echo.
echo ====================================
echo   SUCCESS!
echo   Installer: dist-installer\ServerMon-Setup.exe
echo ====================================
pause
