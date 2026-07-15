@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_EXE="
for %%I in (python.exe) do set "PYTHON_EXE=%%~$PATH:I"
if not defined PYTHON_EXE exit /b 9009

set "PYTHONW_EXE=%PYTHON_EXE:python.exe=pythonw.exe%"
if exist "%PYTHONW_EXE%" (
  start "xmplayer" /max "%PYTHONW_EXE%" "%~dp0run_gui.py"
) else (
  start "xmplayer" /max "%PYTHON_EXE%" "%~dp0run_gui.py"
)

exit /b 0
