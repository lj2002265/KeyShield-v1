@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH="
if not exist ".venv\Scripts\python.exe" (
  python -c "import sys; assert sys.version_info >= (3,10)" >nul 2>&1
  if errorlevel 1 (
    echo Python 3.10+ is required. Or download the Windows installer from Releases.
    pause
    exit /b 1
  )
  python -m venv .venv
  if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements-lock.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" desktop_launcher.py --serve
if errorlevel 1 goto failed
exit /b 0
:failed
echo Setup or launch failed. See the message above.
pause
exit /b 1
