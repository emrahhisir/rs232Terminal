#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RS232 Cift COM Port Paralel Dosya Transfer Uygulamasi
Gereksinimler: pip install pyqt5 pyserial pyzipper
"""

import sys
import os
import struct
import zlib
import threading
import time
import io
from pathlib import Path
from typing import List, Dict, Tuple, Optional

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("pyserial kurulu degil: pip install pyserial")
    sys.exit(1)

try:
    import pyzipper
except ImportError:
    print("pyzipper kurulu degil: pip install pyzipper")
    sys.exit(1)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QProgressBar, QTextEdit,
    QFileDialog, QComboBox, QGroupBox, QTabWidget, QListWidget,
    QListWidgetItem, QMessageBox, QCheckBox, QSizePolicy, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor

# ==============================================================================
# PROTOCOL
# ==============================================================================

MAGIC = b'\xAA\x55\xA5\x5A'

PKT_READY = 0x01   # Alici hazir
PKT_INFO  = 0x02   # Transfer bilgisi: total_chunks(4) + zip_size(8)
PKT_DATA  = 0x03   # Veri chunk'i, seq = chunk indisi
PKT_EOF   = 0x04   # Port transferi bitti
PKT_ACK   = 0x05   # Onay, seq = onaylanan chunk indisi
PKT_NAK   = 0x06   # Hata, seq = hata chunk indisi
PKT_ABORT = 0x07   # Transfer iptal

# Paket yapisi: MAGIC(4) + TIP(1) + SEQ(4) + UZUNLUK(2) + VERI + CRC32(4)
HDR_FMT  = '>4sBIH'
HDR_SIZE = struct.calcsize(HDR_FMT)   # 4+1+4+2 = 11

MAX_DENEME   = 5
ACK_BEKLEME  = 8.0    # saniye
HAZIR_BEKLEME = 60.0  # saniye
VARSAYILAN_CHUNK = 512


def paket_olustur(tip: int, seq: int, veri: bytes = b'') -> bytes:
    hdr  = struct.pack(HDR_FMT, MAGIC, tip, seq, len(veri))
    govde = hdr + veri
    crc  = struct.pack('>I', zlib.crc32(govde) & 0xFFFFFFFF)
    return govde + crc


def paket_oku(ser: serial.Serial, bekleme: float = 10.0) -> Tuple[int, int, bytes]:
    """
    Seri porttan gecerli bir paket okur.
    (tip, seq, veri) dondurur veya TimeoutError firlatir.
    """
    buf = bytearray()
    bitis = time.monotonic() + bekleme

    while True:
        if time.monotonic() > bitis:
            raise TimeoutError(f"Paket okuma zaman asimi ({bekleme:.0f}s)")

        bekleyen = ser.in_waiting
        if bekleyen > 0:
            buf += ser.read(bekleyen)
        else:
            b = ser.read(1)
            if b:
                buf += b

        while len(buf) >= HDR_SIZE + 4:
            idx = bytes(buf).find(MAGIC)
            if idx == -1:
                buf = buf[-3:] if len(buf) > 3 else buf
                break
            if idx > 0:
                buf = buf[idx:]

            if len(buf) < HDR_SIZE:
                break

            try:
                _, tip, seq, veri_uzunlugu = struct.unpack(HDR_FMT, bytes(buf[:HDR_SIZE]))
            except struct.error:
                buf = buf[4:]
                continue

            toplam = HDR_SIZE + veri_uzunlugu + 4
            if len(buf) < toplam:
                break

            govde = bytes(buf[:HDR_SIZE + veri_uzunlugu])
            crc_al = struct.unpack('>I', bytes(buf[HDR_SIZE + veri_uzunlugu:toplam]))[0]

            if (zlib.crc32(govde) & 0xFFFFFFFF) == crc_al:
                veri = bytes(buf[HDR_SIZE:HDR_SIZE + veri_uzunlugu])
                del buf[:toplam]
                return tip, seq, veri
            else:
                del buf[:4]  # bozuk magic'i atla

        time.sleep(0.001)


# ==============================================================================
# ZIP YARDIMCI FONKSIYONLAR
# ==============================================================================

def zip_olustur(ogeler: List[str], sifre: str) -> bytes:
    """Dosya ve dizinleri AES-256 sifreli zip'e pakitle."""
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, 'w',
                              compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(sifre.encode('utf-8'))
        for oge in ogeler:
            p = Path(oge)
            if p.is_file():
                zf.write(p, p.name)
            elif p.is_dir():
                for f in sorted(p.rglob('*')):
                    if f.is_file():
                        zf.write(f, str(f.relative_to(p.parent)))
    return buf.getvalue()


def zip_ac(veri: bytes, sifre: str, hedef: str) -> None:
    """AES-256 sifreli zip'i hedef dizine cikar."""
    buf = io.BytesIO(veri)
    with pyzipper.AESZipFile(buf, 'r') as zf:
        zf.setpassword(sifre.encode('utf-8'))
        zf.extractall(hedef)


# ==============================================================================
# PORT GONDERME THREAD'I
# ==============================================================================

class PortGonderThread(QThread):
    sinyal_ilerleme = pyqtSignal(int, int)   # port_idx, 0-100
    sinyal_log      = pyqtSignal(str)
    sinyal_bitti    = pyqtSignal(int, bool)  # port_idx, basarili

    def __init__(self, port_idx: int, port_adi: str, baud: int,
                 benim_chunklar: List[Tuple[int, bytes]],
                 toplam_chunk: int, zip_boyutu: int,
                 bariyer: Optional[threading.Barrier] = None):
        super().__init__()
        self.port_idx       = port_idx
        self.port_adi       = port_adi
        self.baud           = baud
        self.benim_chunklar = benim_chunklar
        self.toplam_chunk   = toplam_chunk
        self.zip_boyutu     = zip_boyutu
        self.bariyer        = bariyer
        self.basarili       = False
        self._dur           = False

    def dur(self):
        self._dur = True

    def run(self):
        pi = self.port_idx
        try:
            ser = serial.Serial(
                self.port_adi, self.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1, write_timeout=5,
                rtscts=False, dsrdtr=False
            )
            ser.reset_output_buffer()
        except serial.SerialException as e:
            self.sinyal_log.emit(f"[Port{pi+1}] Acılamadı: {e}")
            self.sinyal_bitti.emit(pi, False)
            return

        try:
            self.basarili = self._gonder(ser)
        except Exception as e:
            self.sinyal_log.emit(f"[Port{pi+1}] Beklenmedik hata: {e}")
            self.basarili = False
        finally:
            ser.close()

        self.sinyal_bitti.emit(pi, self.basarili)

    def _gonder(self, ser: serial.Serial) -> bool:
        pi = self.port_idx
        self.sinyal_log.emit(f"[Port{pi+1}] Alici bekleniyor...")

        # READY bekle — yanlış tipli paket veya timeout gelirse yoksay,
        # deadline dolana kadar tekrar dene (continue, break degil)
        bitis = time.monotonic() + HAZIR_BEKLEME
        hazir = False
        while time.monotonic() < bitis:
            kalan = bitis - time.monotonic()
            try:
                tip, _, _ = paket_oku(ser, min(kalan, 2.0))
                if tip == PKT_READY:
                    hazir = True
                    break
                if tip == PKT_ABORT:
                    self.sinyal_log.emit(f"[Port{pi+1}] ABORT alindi")
                    return False
                self.sinyal_log.emit(f"[Port{pi+1}] READY bekleniyor, gelen tip: {tip:#x} (yoksayildi)")
            except TimeoutError:
                continue  # Süre varsa döngüye devam et
        if not hazir:
            self.sinyal_log.emit(f"[Port{pi+1}] Alici READY gondermedi (zaman asimi)")
            return False

        self.sinyal_log.emit(f"[Port{pi+1}] Alici hazir — INFO gonderiliyor...")

        # INFO paketi gonder, ACK bekle
        # Not: alici periyodik READY gonderiyor olabilir, bunlari yoksay
        info_veri = struct.pack('>IQ', self.toplam_chunk, self.zip_boyutu)
        for deneme in range(MAX_DENEME):
            ser.write(paket_olustur(PKT_INFO, 0, info_veri))
            bitis_ack = time.monotonic() + ACK_BEKLEME
            ack_alindi = False
            while time.monotonic() < bitis_ack:
                kalan = bitis_ack - time.monotonic()
                try:
                    tip, _, _ = paket_oku(ser, min(kalan, 2.0))
                    if tip == PKT_ACK:
                        ack_alindi = True
                        break
                    if tip == PKT_ABORT:
                        self.sinyal_log.emit(f"[Port{pi+1}] ABORT alindi")
                        return False
                    # READY veya baska tip: yoksay, ACK beklemeye devam
                except TimeoutError:
                    break
            if ack_alindi:
                break
            self.sinyal_log.emit(f"[Port{pi+1}] INFO ACK bekleniyor ({deneme+1}/{MAX_DENEME})...")
        else:
            self.sinyal_log.emit(f"[Port{pi+1}] INFO ACK alinamadi, iptal")
            return False

        # Senkronizasyon bariyeri: diger port da handshake tamamlayana kadar bekle.
        # Boylece her iki port chunk gondermeye ayni anda baslar; bant genisligi adil paylasilir.
        if self.bariyer is not None:
            self.sinyal_log.emit(f"[Port{pi+1}] Diger port hazir olana kadar bekleniyor...")
            try:
                self.bariyer.wait(timeout=90)
                self.sinyal_log.emit(f"[Port{pi+1}] Senkronizasyon tamam — transfer basliyor")
            except threading.BrokenBarrierError:
                self.sinyal_log.emit(f"[Port{pi+1}] Senkronizasyon basarisiz (diger port hazir olamadi)")
                return False

        # Chunk'lari gonder
        toplam = len(self.benim_chunklar)
        for i, (seq, veri) in enumerate(self.benim_chunklar):
            if self._dur:
                ser.write(paket_olustur(PKT_ABORT, 0))
                self.sinyal_log.emit(f"[Port{pi+1}] Transfer iptal edildi")
                return False

            for deneme in range(MAX_DENEME):
                ser.write(paket_olustur(PKT_DATA, seq, veri))
                # ACK bekleme: dogru seq ACK gelene kadar veya timeout
                bitis_ack = time.monotonic() + ACK_BEKLEME
                ack_alindi = False
                while time.monotonic() < bitis_ack:
                    kalan = bitis_ack - time.monotonic()
                    try:
                        tip, ack_seq, _ = paket_oku(ser, min(kalan, 2.0))
                        if tip == PKT_ACK and ack_seq == seq:
                            ack_alindi = True
                            break
                        if tip == PKT_ABORT:
                            self.sinyal_log.emit(f"[Port{pi+1}] Alici ABORT gonderdi")
                            return False
                        # Farkli seq ACK veya baska paket — yoksay, devam et
                    except TimeoutError:
                        break
                if ack_alindi:
                    break
                self.sinyal_log.emit(
                    f"[Port{pi+1}] Chunk {seq} tekrar gonderiliyor ({deneme+1}/{MAX_DENEME})..."
                )
            else:
                self.sinyal_log.emit(f"[Port{pi+1}] Chunk {seq} gonderilemedi, iptal")
                return False

            pct = int((i + 1) * 100 / toplam)
            self.sinyal_ilerleme.emit(pi, pct)

        ser.write(paket_olustur(PKT_EOF, 0))
        self.sinyal_log.emit(f"[Port{pi+1}] Tum chunklar gonderildi ({toplam} adet)")
        return True


# ==============================================================================
# PORT ALMA THREAD'I
# ==============================================================================

class PortAlThread(QThread):
    sinyal_ilerleme = pyqtSignal(int, int)          # port_idx, 0-100
    sinyal_log      = pyqtSignal(str)
    sinyal_chunk    = pyqtSignal(int, int, bytes)    # port_idx, seq, veri
    sinyal_info     = pyqtSignal(int, int, int)      # port_idx, toplam_chunk, zip_boyutu
    sinyal_bitti    = pyqtSignal(int, bool)          # port_idx, basarili

    def __init__(self, port_idx: int, port_adi: str, baud: int,
                 tek_port: bool = False,
                 bariyer: Optional[threading.Barrier] = None):
        super().__init__()
        self.port_idx  = port_idx
        self.port_adi  = port_adi
        self.baud      = baud
        self.tek_port  = tek_port
        self.bariyer   = bariyer
        self.basarili  = False
        self._dur      = False
        self._benim_toplam = 0

    def dur(self):
        self._dur = True

    def run(self):
        pi = self.port_idx
        try:
            ser = serial.Serial(
                self.port_adi, self.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1, write_timeout=5,
                rtscts=False, dsrdtr=False
            )
            ser.reset_output_buffer()
        except serial.SerialException as e:
            self.sinyal_log.emit(f"[Port{pi+1}] Acılamadı: {e}")
            self.sinyal_bitti.emit(pi, False)
            return

        try:
            self.basarili = self._al(ser)
        except Exception as e:
            self.sinyal_log.emit(f"[Port{pi+1}] Beklenmedik hata: {e}")
            self.basarili = False
        finally:
            ser.close()

        self.sinyal_bitti.emit(pi, self.basarili)

    def _al(self, ser: serial.Serial) -> bool:
        pi = self.port_idx

        # INFO gelene kadar periyodik READY gonder (her ~2s'de bir tekrarla).
        # Boylece gonderici ne zaman baslarsa baslasin READY'yi yakalar,
        # port acilindan sonra karsinin gonderdiği READY kaybolsa bile sorun olmaz.
        self.sinyal_log.emit(f"[Port{pi+1}] Gonderici bekleniyor (READY gonderiliyor)...")
        bitis = time.monotonic() + HAZIR_BEKLEME
        info_veri = None
        while time.monotonic() < bitis:
            ser.write(paket_olustur(PKT_READY, 0))
            kalan = bitis - time.monotonic()
            try:
                tip, _, veri = paket_oku(ser, min(kalan, 2.0))
                if tip == PKT_INFO and len(veri) >= 12:
                    info_veri = veri
                    break
                if tip == PKT_ABORT:
                    self.sinyal_log.emit(f"[Port{pi+1}] ABORT alindi")
                    return False
                self.sinyal_log.emit(f"[Port{pi+1}] INFO bekleniyor, gelen tip: {tip:#x} (yoksayildi)")
            except TimeoutError:
                continue  # Tekrar READY gonder
        if info_veri is None:
            self.sinyal_log.emit(f"[Port{pi+1}] INFO paketi alinamadi (zaman asimi)")
            return False
        veri = info_veri

        toplam_chunk, zip_boyutu = struct.unpack('>IQ', veri[:12])
        self.sinyal_log.emit(
            f"[Port{pi+1}] INFO: {toplam_chunk} chunk, {zip_boyutu:,} byte"
        )
        self.sinyal_info.emit(pi, toplam_chunk, zip_boyutu)

        if self.tek_port:
            self._benim_toplam = toplam_chunk
        else:
            # port0 = cift indisler (0,2,4,...) → ceil(toplam/2)
            # port1 = tek indisler (1,3,5,...) → floor(toplam/2)
            self._benim_toplam = (toplam_chunk + (1 - pi)) // 2

        ser.write(paket_olustur(PKT_ACK, 0))

        # Senkronizasyon bariyeri: diger port da handshake tamamlayana kadar bekle
        if self.bariyer is not None:
            try:
                self.bariyer.wait(timeout=90)
            except threading.BrokenBarrierError:
                self.sinyal_log.emit(f"[Port{pi+1}] Senkronizasyon basarisiz")
                return False

        # Chunklari al
        alinan = 0
        while not self._dur:
            try:
                tip, seq, veri = paket_oku(ser, 60.0)
            except TimeoutError as e:
                self.sinyal_log.emit(f"[Port{pi+1}] {e}")
                return False

            if tip == PKT_EOF:
                self.sinyal_log.emit(f"[Port{pi+1}] EOF — {alinan} chunk alindi")
                break
            elif tip == PKT_ABORT:
                self.sinyal_log.emit(f"[Port{pi+1}] Transfer iptal edildi")
                return False
            elif tip == PKT_DATA:
                ser.write(paket_olustur(PKT_ACK, seq))
                self.sinyal_chunk.emit(pi, seq, veri)
                alinan += 1
                if self._benim_toplam > 0:
                    pct = int(alinan * 100 / self._benim_toplam)
                    self.sinyal_ilerleme.emit(pi, min(pct, 100))
            else:
                ser.write(paket_olustur(PKT_NAK, seq))

        return True


# ==============================================================================
# GONDERME YONETICISI
# ==============================================================================

class GonderYoneticisi(QThread):
    sinyal_genel    = pyqtSignal(int)        # 0-100
    sinyal_port     = pyqtSignal(int, int)   # port_idx, 0-100
    sinyal_log      = pyqtSignal(str)
    sinyal_bitti    = pyqtSignal(bool, str)

    def __init__(self, ogeler: List[str], sifre: str,
                 port1: str, port2: str, baud1: int, baud2: int,
                 chunk_boyutu: int = VARSAYILAN_CHUNK,
                 tek_port: bool = False):
        super().__init__()
        self.ogeler      = ogeler
        self.sifre       = sifre
        self.port1       = port1
        self.port2       = port2
        self.baud1       = baud1
        self.baud2       = baud2
        self.chunk_boyutu = chunk_boyutu
        self.tek_port    = tek_port
        self._yuzde      = [0, 0]
        self._kilit      = threading.Lock()

    def run(self):
        self.sinyal_log.emit("Sifreli ZIP olusturuluyor...")
        try:
            zip_verisi = zip_olustur(self.ogeler, self.sifre)
        except Exception as e:
            self.sinyal_bitti.emit(False, f"ZIP hatasi: {e}")
            return

        n = len(zip_verisi)
        self.sinyal_log.emit(f"ZIP hazir: {n:,} byte")

        # Chunk'lara bol
        tum_chunklar: List[Tuple[int, bytes]] = []
        for i, offset in enumerate(range(0, n, self.chunk_boyutu)):
            tum_chunklar.append((i, zip_verisi[offset:offset + self.chunk_boyutu]))

        toplam = len(tum_chunklar)

        if self.tek_port:
            self.sinyal_log.emit(f"Toplam {toplam} chunk → Port1: {toplam} (tek port modu)")
            t0 = PortGonderThread(0, self.port1, self.baud1, tum_chunklar, toplam, n)
            t0.sinyal_ilerleme.connect(self._ilerleme_guncelle)
            t0.sinyal_log.connect(self.sinyal_log)
            t0.start()
            t0.wait()
            ok = t0.basarili
        else:
            c0 = [(s, d) for s, d in tum_chunklar if s % 2 == 0]
            c1 = [(s, d) for s, d in tum_chunklar if s % 2 == 1]
            self.sinyal_log.emit(
                f"Toplam {toplam} chunk → Port1: {len(c0)}, Port2: {len(c1)}"
            )
            bariyer = threading.Barrier(2)
            t0 = PortGonderThread(0, self.port1, self.baud1, c0, toplam, n, bariyer=bariyer)
            t1 = PortGonderThread(1, self.port2, self.baud2, c1, toplam, n, bariyer=bariyer)
            for t in (t0, t1):
                t.sinyal_ilerleme.connect(self._ilerleme_guncelle)
                t.sinyal_log.connect(self.sinyal_log)
            t0.start()
            t1.start()
            t0.wait()
            t1.wait()
            ok = t0.basarili and t1.basarili

        msg = "Transfer basariyla tamamlandi!" if ok else "Transfer basarisiz oldu."
        self.sinyal_bitti.emit(ok, msg)

    def _ilerleme_guncelle(self, pi: int, pct: int):
        with self._kilit:
            self._yuzde[pi] = pct
        self.sinyal_port.emit(pi, pct)
        if self.tek_port:
            self.sinyal_genel.emit(pct)
        else:
            self.sinyal_genel.emit((self._yuzde[0] + self._yuzde[1]) // 2)


# ==============================================================================
# ALMA YONETICISI
# ==============================================================================

class AlYoneticisi(QThread):
    sinyal_genel    = pyqtSignal(int)
    sinyal_port     = pyqtSignal(int, int)
    sinyal_log      = pyqtSignal(str)
    sinyal_bitti    = pyqtSignal(bool, str)

    def __init__(self, sifre: str, hedef_dizin: str,
                 port1: str, port2: str, baud1: int, baud2: int,
                 tek_port: bool = False):
        super().__init__()
        self.sifre       = sifre
        self.hedef_dizin = hedef_dizin
        self.port1       = port1
        self.port2       = port2
        self.baud1       = baud1
        self.baud2       = baud2
        self.tek_port    = tek_port
        self._chunklar: Dict[int, bytes] = {}
        self._toplam     = 0
        self._kilit      = threading.Lock()

    def run(self):
        if self.tek_port:
            t0 = PortAlThread(0, self.port1, self.baud1, tek_port=True)
            t0.sinyal_log.connect(self.sinyal_log)
            t0.sinyal_ilerleme.connect(self.sinyal_port)
            t0.sinyal_chunk.connect(self._chunk_alindi)
            t0.sinyal_info.connect(self._info_alindi)
            t0.start()
            t0.wait()
            ok = t0.basarili
        else:
            bariyer = threading.Barrier(2)
            t0 = PortAlThread(0, self.port1, self.baud1, bariyer=bariyer)
            t1 = PortAlThread(1, self.port2, self.baud2, bariyer=bariyer)
            for t in (t0, t1):
                t.sinyal_log.connect(self.sinyal_log)
                t.sinyal_ilerleme.connect(self.sinyal_port)
                t.sinyal_chunk.connect(self._chunk_alindi)
                t.sinyal_info.connect(self._info_alindi)
            t0.start()
            t1.start()
            t0.wait()
            t1.wait()
            ok = t0.basarili and t1.basarili

        if not ok:
            self.sinyal_bitti.emit(False, "Alim basarisiz oldu.")
            return

        self.sinyal_log.emit(f"Chunklar birlestiriliyor ({len(self._chunklar)} adet)...")
        try:
            zip_verisi = b''.join(
                self._chunklar[i] for i in sorted(self._chunklar)
            )
        except KeyError as e:
            self.sinyal_bitti.emit(False, f"Eksik chunk: {e}")
            return

        self.sinyal_log.emit(f"ZIP aciliyor ({len(zip_verisi):,} byte) → {self.hedef_dizin}")
        try:
            os.makedirs(self.hedef_dizin, exist_ok=True)
            zip_ac(zip_verisi, self.sifre, self.hedef_dizin)
            self.sinyal_bitti.emit(
                True, f"Dosyalar '{self.hedef_dizin}' klasorune cikarildi."
            )
        except Exception as e:
            self.sinyal_bitti.emit(False, f"ZIP acma hatasi: {e}")

    def _chunk_alindi(self, pi: int, seq: int, veri: bytes):
        with self._kilit:
            self._chunklar[seq] = veri
            alinan = len(self._chunklar)
            if self._toplam > 0:
                self.sinyal_genel.emit(int(alinan * 100 / self._toplam))

    def _info_alindi(self, pi: int, toplam: int, zip_boyutu: int):
        with self._kilit:
            if not self._toplam:
                self._toplam = toplam
                self.sinyal_log.emit(
                    f"Transfer bilgisi: {toplam} chunk, {zip_boyutu:,} byte"
                )


# ==============================================================================
# UI BILESENLERI
# ==============================================================================

BAUD_ORANLARI = ['9600', '19200', '38400', '57600', '115200',
                  '230400', '460800', '921600']
CHUNK_BOYUTLARI = ['128', '256', '512', '1024', '2048', '4096']


def portlari_listele() -> List[str]:
    return [p.device for p in serial.tools.list_ports.comports()]


class PortSeciciWidget(QGroupBox):
    def __init__(self, baslik: str, parent=None):
        super().__init__(baslik, parent)
        duzen = QHBoxLayout(self)
        duzen.setSpacing(6)

        duzen.addWidget(QLabel("Port:"))
        self.port_combo = QComboBox()
        self.port_combo.setMinimumWidth(130)
        duzen.addWidget(self.port_combo)

        yenile_btn = QPushButton("↻")
        yenile_btn.setFixedWidth(28)
        yenile_btn.setToolTip("Portlari Yenile")
        yenile_btn.clicked.connect(self.yenile)
        duzen.addWidget(yenile_btn)

        duzen.addWidget(QLabel("Baud:"))
        self.baud_combo = QComboBox()
        for b in BAUD_ORANLARI:
            self.baud_combo.addItem(b)
        self.baud_combo.setCurrentText('115200')
        duzen.addWidget(self.baud_combo)

        duzen.addStretch()
        self.yenile()

    def yenile(self):
        mevcut = self.port_combo.currentText()
        self.port_combo.clear()
        for p in portlari_listele():
            self.port_combo.addItem(p)
        idx = self.port_combo.findText(mevcut)
        if idx >= 0:
            self.port_combo.setCurrentIndex(idx)

    @property
    def port(self) -> str:
        return self.port_combo.currentText()

    @property
    def baud(self) -> int:
        return int(self.baud_combo.currentText())


class LogAlani(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont('Courier New', 9))
        self.setMinimumHeight(120)
        self.setMaximumHeight(180)

    def log_ekle(self, mesaj: str):
        zaman = time.strftime('%H:%M:%S')
        self.append(f"[{zaman}] {mesaj}")
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())


def ilerleme_satiri_olustur(etiket: str, ana_duzen: QVBoxLayout) -> QProgressBar:
    satir = QHBoxLayout()
    lbl = QLabel(etiket)
    lbl.setFixedWidth(75)
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setValue(0)
    bar.setTextVisible(True)
    satir.addWidget(lbl)
    satir.addWidget(bar)
    ana_duzen.addLayout(satir)
    return bar


# ==============================================================================
# GONDER SEKMESI
# ==============================================================================

class GonderSekmesi(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._yonetici: Optional[GonderYoneticisi] = None
        self._ui_olustur()

    def _ui_olustur(self):
        ana = QVBoxLayout(self)
        ana.setSpacing(8)

        # --- Dosya listesi ---
        dosya_grup = QGroupBox("Gonderilecek Dosya / Dizinler")
        dg = QVBoxLayout(dosya_grup)

        self.dosya_listesi = QListWidget()
        self.dosya_listesi.setMinimumHeight(110)
        self.dosya_listesi.setAlternatingRowColors(True)
        dg.addWidget(self.dosya_listesi)

        btn_satir = QHBoxLayout()
        for metin, slot in [
            ("+ Dosya Ekle", self._dosya_ekle),
            ("+ Dizin Ekle", self._dizin_ekle),
            ("Secileni Kaldir", self._kaldir),
            ("Listeyi Temizle", self.dosya_listesi.clear),
        ]:
            b = QPushButton(metin)
            b.clicked.connect(slot)
            btn_satir.addWidget(b)
        dg.addLayout(btn_satir)
        ana.addWidget(dosya_grup)

        # --- Port modu ---
        mod_satir = QHBoxLayout()
        self.tek_port_cb = QCheckBox("Tek Port Modu (sadece Port 1 kullanilir)")
        self.tek_port_cb.toggled.connect(self._tek_port_guncelle)
        mod_satir.addWidget(self.tek_port_cb)
        mod_satir.addStretch()
        ana.addLayout(mod_satir)

        # --- Port ayarlari ---
        port_satir = QHBoxLayout()
        self.port1 = PortSeciciWidget("Port 1 (Cift indisler: 0, 2, 4...)")
        self.port2 = PortSeciciWidget("Port 2 (Tek indisler: 1, 3, 5...)")
        port_satir.addWidget(self.port1)
        port_satir.addWidget(self.port2)
        ana.addLayout(port_satir)

        # --- Sifre + chunk boyutu ---
        opt_satir = QHBoxLayout()

        sifre_grup = QGroupBox("Sifre")
        sg = QHBoxLayout(sifre_grup)
        self.sifre_giris = QLineEdit()
        self.sifre_giris.setEchoMode(QLineEdit.Password)
        self.sifre_giris.setPlaceholderText("ZIP sifresi...")
        sg.addWidget(self.sifre_giris)
        self.sifre_goster = QCheckBox("Goster")
        self.sifre_goster.toggled.connect(
            lambda c: self.sifre_giris.setEchoMode(
                QLineEdit.Normal if c else QLineEdit.Password
            )
        )
        sg.addWidget(self.sifre_goster)
        opt_satir.addWidget(sifre_grup, 3)

        chunk_grup = QGroupBox("Chunk Boyutu")
        cg = QHBoxLayout(chunk_grup)
        self.chunk_combo = QComboBox()
        for c in CHUNK_BOYUTLARI:
            self.chunk_combo.addItem(f"{c} B")
        self.chunk_combo.setCurrentText("512 B")
        cg.addWidget(self.chunk_combo)
        opt_satir.addWidget(chunk_grup, 1)

        ana.addLayout(opt_satir)

        # --- Ilerleme cubuklar ---
        ilerleme_grup = QGroupBox("Ilerleme")
        ig = QVBoxLayout(ilerleme_grup)
        self.bar_port1   = ilerleme_satiri_olustur("Port 1:", ig)
        self.bar_port2   = ilerleme_satiri_olustur("Port 2:", ig)
        self.bar_genel   = ilerleme_satiri_olustur("Toplam: ", ig)
        ana.addWidget(ilerleme_grup)

        # --- Log ---
        log_grup = QGroupBox("Islem Gunlugu")
        lg = QVBoxLayout(log_grup)
        self.log = LogAlani()
        lg.addWidget(self.log)
        ana.addWidget(log_grup)

        # --- Gonder butonu ---
        self.btn_gonder = QPushButton("GONDER")

        self.btn_gonder.setFixedHeight(42)
        self.btn_gonder.setFont(QFont('Arial', 12, QFont.Bold))
        self.btn_gonder.clicked.connect(self._gonderi_baslat)
        ana.addWidget(self.btn_gonder)

    # -- Yardimci metodlar --

    def _tek_port_guncelle(self, tek: bool):
        self.port2.setEnabled(not tek)
        self.bar_port2.setEnabled(not tek)
        if tek:
            self.bar_port2.setValue(0)
        self.port1.setTitle(
            "Port 1" if tek else "Port 1 (Cift indisler: 0, 2, 4...)"
        )

    def _dosya_ekle(self):
        dosyalar, _ = QFileDialog.getOpenFileNames(self, "Dosya Sec")
        for d in dosyalar:
            if not self._listede_mi(d):
                self.dosya_listesi.addItem(QListWidgetItem(d))

    def _dizin_ekle(self):
        d = QFileDialog.getExistingDirectory(self, "Dizin Sec")
        if d and not self._listede_mi(d):
            self.dosya_listesi.addItem(QListWidgetItem(d))

    def _kaldir(self):
        for item in self.dosya_listesi.selectedItems():
            self.dosya_listesi.takeItem(self.dosya_listesi.row(item))

    def _listede_mi(self, yol: str) -> bool:
        return any(
            self.dosya_listesi.item(i).text() == yol
            for i in range(self.dosya_listesi.count())
        )

    def _ogeler(self) -> List[str]:
        return [
            self.dosya_listesi.item(i).text()
            for i in range(self.dosya_listesi.count())
        ]

    def _chunk_boyutu(self) -> int:
        return int(self.chunk_combo.currentText().replace(' B', ''))

    def _gonderi_baslat(self):
        ogeler = self._ogeler()
        if not ogeler:
            QMessageBox.warning(self, "Uyari", "Gonderilecek dosya/dizin secilmedi.")
            return

        sifre = self.sifre_giris.text()
        if not sifre:
            QMessageBox.warning(self, "Uyari", "Sifre girmediniz.")
            return

        tek_port = self.tek_port_cb.isChecked()
        p1 = self.port1.port
        p2 = self.port2.port
        if not p1:
            QMessageBox.warning(self, "Uyari", "Port 1 secilmedi.")
            return
        if not tek_port:
            if not p2:
                QMessageBox.warning(self, "Uyari", "Port 2 secilmedi.")
                return
            if p1 == p2:
                QMessageBox.warning(self, "Uyari", "Iki port birbirinden farkli olmali.")
                return

        self.btn_gonder.setEnabled(False)
        for bar in (self.bar_port1, self.bar_port2, self.bar_genel):
            bar.setValue(0)

        self._yonetici = GonderYoneticisi(
            ogeler, sifre, p1, p2,
            self.port1.baud, self.port2.baud,
            self._chunk_boyutu(), tek_port
        )
        self._yonetici.sinyal_log.connect(self.log.log_ekle)
        self._yonetici.sinyal_port.connect(self._port_ilerleme)
        self._yonetici.sinyal_genel.connect(self.bar_genel.setValue)
        self._yonetici.sinyal_bitti.connect(self._tamamlandi)
        self._yonetici.start()

    def _port_ilerleme(self, pi: int, pct: int):
        [self.bar_port1, self.bar_port2][pi].setValue(pct)

    def _tamamlandi(self, ok: bool, mesaj: str):
        self.btn_gonder.setEnabled(True)
        self.log.log_ekle(mesaj)
        if ok:
            for bar in (self.bar_port1, self.bar_port2, self.bar_genel):
                bar.setValue(100)
            QMessageBox.information(self, "Basarili", mesaj)
        else:
            QMessageBox.critical(self, "Hata", mesaj)


# ==============================================================================
# AL SEKMESI
# ==============================================================================

class AlSekmesi(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._yonetici: Optional[AlYoneticisi] = None
        self._ui_olustur()

    def _ui_olustur(self):
        ana = QVBoxLayout(self)
        ana.setSpacing(8)

        # --- Cikti dizini ---
        cikti_grup = QGroupBox("Cikti Klasoru")
        cg = QHBoxLayout(cikti_grup)
        self.cikti_giris = QLineEdit()
        self.cikti_giris.setPlaceholderText("Dosyalarin kaydedilecegi klasor...")
        cg.addWidget(self.cikti_giris)
        gozat_btn = QPushButton("Gozat...")
        gozat_btn.clicked.connect(self._cikti_sec)
        cg.addWidget(gozat_btn)
        ana.addWidget(cikti_grup)

        # --- Port modu ---
        mod_satir = QHBoxLayout()
        self.tek_port_cb = QCheckBox("Tek Port Modu (sadece Port 1 kullanilir)")
        self.tek_port_cb.toggled.connect(self._tek_port_guncelle)
        mod_satir.addWidget(self.tek_port_cb)
        mod_satir.addStretch()
        ana.addLayout(mod_satir)

        # --- Port ayarlari ---
        port_satir = QHBoxLayout()
        self.port1 = PortSeciciWidget("Port 1")
        self.port2 = PortSeciciWidget("Port 2")
        port_satir.addWidget(self.port1)
        port_satir.addWidget(self.port2)
        ana.addLayout(port_satir)

        # --- Sifre ---
        sifre_grup = QGroupBox("Sifre (Gondericidekiyle ayni olmali)")
        sg = QHBoxLayout(sifre_grup)
        self.sifre_giris = QLineEdit()
        self.sifre_giris.setEchoMode(QLineEdit.Password)
        self.sifre_giris.setPlaceholderText("ZIP sifresi...")
        sg.addWidget(self.sifre_giris)
        self.sifre_goster = QCheckBox("Goster")
        self.sifre_goster.toggled.connect(
            lambda c: self.sifre_giris.setEchoMode(
                QLineEdit.Normal if c else QLineEdit.Password
            )
        )
        sg.addWidget(self.sifre_goster)
        ana.addWidget(sifre_grup)

        # --- Ilerleme ---
        ilerleme_grup = QGroupBox("Ilerleme")
        ig = QVBoxLayout(ilerleme_grup)
        self.bar_port1   = ilerleme_satiri_olustur("Port 1:", ig)
        self.bar_port2   = ilerleme_satiri_olustur("Port 2:", ig)
        self.bar_genel   = ilerleme_satiri_olustur("Toplam: ", ig)
        ana.addWidget(ilerleme_grup)

        # --- Log ---
        log_grup = QGroupBox("Islem Gunlugu")
        lg = QVBoxLayout(log_grup)
        self.log = LogAlani()
        lg.addWidget(self.log)
        ana.addWidget(log_grup)

        # --- Al butonu ---
        self.btn_al = QPushButton("AL")
        self.btn_al.setFixedHeight(42)
        self.btn_al.setFont(QFont('Arial', 12, QFont.Bold))
        self.btn_al.clicked.connect(self._alimi_baslat)
        ana.addWidget(self.btn_al)

    def _tek_port_guncelle(self, tek: bool):
        self.port2.setEnabled(not tek)
        self.bar_port2.setEnabled(not tek)
        if tek:
            self.bar_port2.setValue(0)

    def _cikti_sec(self):
        d = QFileDialog.getExistingDirectory(self, "Cikti Klasoru Sec")
        if d:
            self.cikti_giris.setText(d)

    def _alimi_baslat(self):
        cikti = self.cikti_giris.text().strip()
        if not cikti:
            QMessageBox.warning(self, "Uyari", "Cikti klasoru secilmedi.")
            return

        sifre = self.sifre_giris.text()
        if not sifre:
            QMessageBox.warning(self, "Uyari", "Sifre girmediniz.")
            return

        tek_port = self.tek_port_cb.isChecked()
        p1 = self.port1.port
        p2 = self.port2.port
        if not p1:
            QMessageBox.warning(self, "Uyari", "Port 1 secilmedi.")
            return
        if not tek_port:
            if not p2:
                QMessageBox.warning(self, "Uyari", "Port 2 secilmedi.")
                return
            if p1 == p2:
                QMessageBox.warning(self, "Uyari", "Iki port birbirinden farkli olmali.")
                return

        self.btn_al.setEnabled(False)
        for bar in (self.bar_port1, self.bar_port2, self.bar_genel):
            bar.setValue(0)

        self._yonetici = AlYoneticisi(
            sifre, cikti, p1, p2,
            self.port1.baud, self.port2.baud, tek_port
        )
        self._yonetici.sinyal_log.connect(self.log.log_ekle)
        self._yonetici.sinyal_port.connect(self._port_ilerleme)
        self._yonetici.sinyal_genel.connect(self.bar_genel.setValue)
        self._yonetici.sinyal_bitti.connect(self._tamamlandi)
        self._yonetici.start()

    def _port_ilerleme(self, pi: int, pct: int):
        [self.bar_port1, self.bar_port2][pi].setValue(pct)

    def _tamamlandi(self, ok: bool, mesaj: str):
        self.btn_al.setEnabled(True)
        self.log.log_ekle(mesaj)
        if ok:
            for bar in (self.bar_port1, self.bar_port2, self.bar_genel):
                bar.setValue(100)
            QMessageBox.information(self, "Basarili", mesaj)
        else:
            QMessageBox.critical(self, "Hata", mesaj)


# ==============================================================================
# ANA PENCERE
# ==============================================================================

class AnaPencere(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RS232 Cift COM Port Paralel Dosya Transferi")
        self.setMinimumSize(820, 680)

        merkez = QWidget()
        self.setCentralWidget(merkez)
        ana = QVBoxLayout(merkez)
        ana.setContentsMargins(10, 10, 10, 10)
        ana.setSpacing(8)

        # Baslik
        baslik = QLabel("RS232 Cift COM Port Paralel Dosya Transferi")
        baslik.setFont(QFont('Arial', 13, QFont.Bold))
        baslik.setAlignment(Qt.AlignCenter)
        ana.addWidget(baslik)

        ayrac = QFrame()
        ayrac.setFrameShape(QFrame.HLine)
        ayrac.setFrameShadow(QFrame.Sunken)
        ana.addWidget(ayrac)

        # Sekmeler
        sekmeler = QTabWidget()
        sekmeler.addTab(GonderSekmesi(), "  Gonder  ")
        sekmeler.addTab(AlSekmesi(), "  Al  ")
        sekmeler.setFont(QFont('Arial', 10))
        ana.addWidget(sekmeler)

        self.statusBar().showMessage(
            "Hazir  |  Her iki tarafta da ayni baud hizini ve sifresini kullanin."
        )


# ==============================================================================
# KOYU TEMA
# ==============================================================================

def koyu_tema_uygula(uygulama: QApplication):
    uygulama.setStyle('Fusion')
    palet = QPalette()
    renk = {
        QPalette.Window:          QColor(45,  45,  48),
        QPalette.WindowText:      QColor(220, 220, 220),
        QPalette.Base:            QColor(30,  30,  30),
        QPalette.AlternateBase:   QColor(45,  45,  48),
        QPalette.ToolTipBase:     QColor(45,  45,  48),
        QPalette.ToolTipText:     QColor(220, 220, 220),
        QPalette.Text:            QColor(220, 220, 220),
        QPalette.Button:          QColor(60,  60,  65),
        QPalette.ButtonText:      QColor(220, 220, 220),
        QPalette.BrightText:      QColor(255, 100, 100),
        QPalette.Link:            QColor(42,  130, 218),
        QPalette.Highlight:       QColor(42,  130, 218),
        QPalette.HighlightedText: QColor(0,   0,   0),
        QPalette.Disabled + QPalette.Text:       QColor(120, 120, 120),
        QPalette.Disabled + QPalette.ButtonText: QColor(120, 120, 120),
    }
    for rol, renk_degeri in renk.items():
        palet.setColor(rol, renk_degeri)
    uygulama.setPalette(palet)

    # Progress bar rengi
    uygulama.setStyleSheet("""
        QProgressBar {
            border: 1px solid #555;
            border-radius: 4px;
            text-align: center;
            background: #222;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #1a73e8, stop:1 #0d9b8c);
            border-radius: 3px;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #555;
            border-radius: 5px;
            margin-top: 8px;
            padding-top: 4px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 4px;
        }
        QPushButton {
            border: 1px solid #666;
            border-radius: 4px;
            padding: 4px 10px;
            background: #3a3a3f;
        }
        QPushButton:hover  { background: #4a4a55; }
        QPushButton:pressed { background: #1a73e8; }
        QPushButton:disabled { color: #777; }
        QTabBar::tab {
            padding: 6px 16px;
            background: #3a3a3f;
            border: 1px solid #555;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected { background: #1a73e8; color: white; }
        QTabBar::tab:hover:!selected { background: #4a4a55; }
        QListWidget {
            border: 1px solid #555;
            border-radius: 3px;
        }
        QLineEdit {
            border: 1px solid #555;
            border-radius: 3px;
            padding: 3px 6px;
            background: #2a2a2e;
        }
        QComboBox {
            border: 1px solid #555;
            border-radius: 3px;
            padding: 3px 6px;
            background: #2a2a2e;
        }
        QComboBox::drop-down { border: none; }
        QTextEdit {
            border: 1px solid #555;
            border-radius: 3px;
            background: #1e1e1e;
        }
    """)


# ==============================================================================
# GIRIS NOKTASI
# ==============================================================================

def main():
    uygulama = QApplication(sys.argv)
    koyu_tema_uygula(uygulama)
    pencere = AnaPencere()
    pencere.show()
    sys.exit(uygulama.exec_())


if __name__ == '__main__':
    main()
