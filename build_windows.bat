@echo off
setlocal
cd /d "%~dp0"
py -m pip install -r requirements-build.txt
if errorlevel 1 exit /b 1
py scripts\build_windows.py
if errorlevel 1 exit /b 1
echo.
echo Build complete. See dist\SPECTRA-Windows-Portable.zip
