@echo off
setlocal
cd /d "%~dp0"
python network_mapper.py
if errorlevel 1 (
  echo.
  echo DeepProbe could not start. Confirm Python 3 with tkinter is installed and available as "python".
  pause
)
