@echo off
REM ============================================================
REM RS232 Transfer - Windows EXE Build Script
REM Gereksinim: Python 3.8+ ve pip yuklu olmali
REM Calistirma: build_windows.bat
REM Cikti: dist\RS232Transfer.exe
REM ============================================================

echo [1/4] Gerekli kutuphaneler yukleniyor...
pip install pyqt5 pyserial pyzipper pyinstaller --quiet
if errorlevel 1 (
    echo HATA: pip install basarisiz.
    pause
    exit /b 1
)

echo [2/4] Onceki build temizleniyor...
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

echo [3/4] EXE olusturuluyor...
pyinstaller rs232_transfer.spec --noconfirm
if errorlevel 1 (
    echo HATA: PyInstaller basarisiz.
    pause
    exit /b 1
)

echo [4/4] Tamamlandi!
echo.
echo  EXE konumu: dist\RS232Transfer.exe
echo  Boyut:
dir /b dist\RS232Transfer.exe 2>nul && for %%I in (dist\RS232Transfer.exe) do echo  %%~zI byte
echo.
pause
