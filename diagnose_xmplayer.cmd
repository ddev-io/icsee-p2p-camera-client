@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_EXE="
for %%I in (python.exe) do set "PYTHON_EXE=%%~$PATH:I"
if not defined PYTHON_EXE (
  echo python.exe not found in PATH
  pause
  exit /b 9009
)

"%PYTHON_EXE%" -u "%~dp0diagnose_xmplayer.py"
echo.
pause
