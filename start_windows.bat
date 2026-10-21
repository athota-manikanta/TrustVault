@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo      TrustVault - Local Windows Start
 echo ==========================================
where py >nul 2>&1
if %errorlevel%==0 (
  set "PYTHON=py"
) else (
  where python >nul 2>&1
  if errorlevel 1 (
    echo Python not found. Install Python from python.org and reopen this file.
    pause
    exit /b 1
  )
  set "PYTHON=python"
)
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating Python environment...
  %PYTHON% -m venv .venv
  if errorlevel 1 goto :fail
)
echo [2/3] Installing necessary packages... (internet required on first start)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :fail
echo [3/3] Configuring local demo and starting server...
".venv\Scripts\python.exe" scripts\local_start.py
if errorlevel 1 goto :fail
pause
exit /b 0
:fail
echo.
echo Something went wrong. Take a screenshot of this window and send it to ChatGPT.
pause
exit /b 1
