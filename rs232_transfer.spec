# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec dosyasi — rs232_transfer.py icin Windows EXE uretir.
Kullanim:
    pyinstaller rs232_transfer.spec
"""

import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT

block_cipher = None

a = Analysis(
    ['rs232_transfer.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'pyzipper',
        'pyzipper.zipfile_aes',
        'serial',
        'serial.tools',
        'serial.tools.list_ports',
        'serial.tools.list_ports_common',
        'serial.tools.list_ports_windows',  # Windows'a ozel
        'PyQt5',
        'PyQt5.QtWidgets',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.sip',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Cipher.AES',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='RS232Transfer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # GUI uygulama — konsol penceresi acilmasin
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # .ico dosyasi varsa buraya yaz: icon='icon.ico'
    version_file=None,
)
