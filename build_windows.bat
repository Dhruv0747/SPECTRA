@echo off
setlocal
cd /d "%~dp0"
py -m pip install --upgrade pyinstaller
pyinstaller --noconfirm --clean --windowed --name SPECTRA --add-data "config;config" --add-data "assets;assets" run_spectra.pyw
echo.
echo Build complete. See dist\SPECTRA\
pause
