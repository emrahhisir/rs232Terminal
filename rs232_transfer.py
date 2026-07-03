#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RS232 Serial Link Terminal
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

PKT_READY = 0x01
PKT_INFO  = 0x02
PKT_DATA  = 0x03
PKT_EOF   = 0x04
PKT_ACK   = 0x05
PKT_NAK   = 0x06
PKT_ABORT = 0x07

# Clipboard (onaysiz, fire-and-forget aktarim)
PKT_CLIP_INFO = 0x10
PKT_CLIP_DATA = 0x11
PKT_CLIP_EOF  = 0x12

HDR_FMT  = '>4sBIH'
HDR_SIZE = struct.calcsize(HDR_FMT)   # 4+1+4+2 = 11

MAX_DENEME   = 5
ACK_BEKLEME  = 8.0
HAZIR_BEKLEME = 60.0
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
    # Tampon seri porta baglanir; boylece bir cagride okunup da o an
    # islenmeyen (birden fazla paketlik) baytlar kaybolmaz, sonraki
    # cagrida kullanilir. (Clipboard gibi arka arkaya paket akislarinda kritik.)
    buf = getattr(ser, '_paket_buf', None)
    if buf is None:
        buf = bytearray()
        ser._paket_buf = buf

    bitis = time.monotonic() + bekleme

    while True:
        if time.monotonic() > bitis:
            raise TimeoutError(f"Packet read timeout ({bekleme:.0f}s)")

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
                # Kismi MAGIC olabilir; son 3 bayti sakla, gerisini at.
                if len(buf) > 3:
                    del buf[:-3]
                break
            if idx > 0:
                del buf[:idx]

            if len(buf) < HDR_SIZE:
                break

            try:
                _, tip, seq, veri_uzunlugu = struct.unpack(HDR_FMT, bytes(buf[:HDR_SIZE]))
            except struct.error:
                del buf[:4]
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
                del buf[:4]

        time.sleep(0.001)


# ==============================================================================
# ZIP YARDIMCI FONKSIYONLAR
# ==============================================================================

def zip_olustur(ogeler: List[str], sifre: str) -> bytes:
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
    buf = io.BytesIO(veri)
    with pyzipper.AESZipFile(buf, 'r') as zf:
        zf.setpassword(sifre.encode('utf-8'))
        zf.extractall(hedef)


CLIP_GIRIS_ADI = 'clipboard.txt'


def clip_zip_olustur(metin: str, sifre: str) -> bytes:
    """Pano metnini AES sifreli bir zip icine paketler."""
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, 'w',
                              compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(sifre.encode('utf-8'))
        zf.writestr(CLIP_GIRIS_ADI, metin.encode('utf-8'))
    return buf.getvalue()


def clip_zip_ac(veri: bytes, sifre: str) -> str:
    """Sifreli zip'ten pano metnini cozer."""
    buf = io.BytesIO(veri)
    with pyzipper.AESZipFile(buf, 'r') as zf:
        zf.setpassword(sifre.encode('utf-8'))
        ham = zf.read(CLIP_GIRIS_ADI)
    return ham.decode('utf-8')


# ==============================================================================
# PORT GONDERME THREAD'I
# ==============================================================================

class PortGonderThread(QThread):
    sinyal_ilerleme = pyqtSignal(int, int)
    sinyal_log      = pyqtSignal(str)
    sinyal_bitti    = pyqtSignal(int, bool)

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
            self.sinyal_log.emit(f"[COM{pi+1}] Open failed: {e}")
            self.sinyal_bitti.emit(pi, False)
            return

        try:
            self.basarili = self._gonder(ser)
        except Exception as e:
            self.sinyal_log.emit(f"[COM{pi+1}] Unexpected error: {e}")
            self.basarili = False
        finally:
            ser.close()

        self.sinyal_bitti.emit(pi, self.basarili)

    def _abort_bariyer(self):
        if self.bariyer is not None:
            try:
                self.bariyer.abort()
            except Exception:
                pass

    def _gonder(self, ser: serial.Serial) -> bool:
        pi = self.port_idx
        self.sinyal_log.emit(f"[COM{pi+1}] Waiting for remote...")

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
                    self.sinyal_log.emit(f"[COM{pi+1}] ABORT received")
                    self._abort_bariyer()
                    return False
                self.sinyal_log.emit(f"[COM{pi+1}] Awaiting READY, got type: {tip:#x} (ignored)")
            except TimeoutError:
                continue
        if not hazir:
            self.sinyal_log.emit(f"[COM{pi+1}] Remote READY timeout")
            self._abort_bariyer()
            return False

        self.sinyal_log.emit(f"[COM{pi+1}] Remote ready — sending INFO...")

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
                        self.sinyal_log.emit(f"[COM{pi+1}] ABORT received")
                        self._abort_bariyer()
                        return False
                except TimeoutError:
                    break
            if ack_alindi:
                break
            self.sinyal_log.emit(f"[COM{pi+1}] INFO ACK wait ({deneme+1}/{MAX_DENEME})...")
        else:
            self.sinyal_log.emit(f"[COM{pi+1}] INFO ACK failed, aborting")
            self._abort_bariyer()
            return False

        if self.bariyer is not None:
            self.sinyal_log.emit(f"[COM{pi+1}] Waiting for peer sync...")
            try:
                self.bariyer.wait(timeout=HAZIR_BEKLEME)
                self.sinyal_log.emit(f"[COM{pi+1}] Sync OK — starting TX")
            except threading.BrokenBarrierError:
                self.sinyal_log.emit(f"[COM{pi+1}] Peer sync failed, aborting")
                return False

        toplam = len(self.benim_chunklar)
        for i, (seq, veri) in enumerate(self.benim_chunklar):
            if self._dur:
                ser.write(paket_olustur(PKT_ABORT, 0))
                self.sinyal_log.emit(f"[COM{pi+1}] Aborted by user")
                return False

            for deneme in range(MAX_DENEME):
                ser.write(paket_olustur(PKT_DATA, seq, veri))
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
                            self.sinyal_log.emit(f"[COM{pi+1}] Remote sent ABORT")
                            return False
                    except TimeoutError:
                        break
                if ack_alindi:
                    break
                self.sinyal_log.emit(
                    f"[COM{pi+1}] Retrying packet {seq} ({deneme+1}/{MAX_DENEME})..."
                )
            else:
                self.sinyal_log.emit(f"[COM{pi+1}] Packet {seq} failed, aborting")
                return False

            pct = int((i + 1) * 100 / toplam)
            self.sinyal_ilerleme.emit(pi, pct)

        ser.write(paket_olustur(PKT_EOF, 0))
        self.sinyal_log.emit(f"[COM{pi+1}] All packets sent ({toplam})")
        return True


# ==============================================================================
# PORT ALMA THREAD'I
# ==============================================================================

class PortAlThread(QThread):
    sinyal_ilerleme = pyqtSignal(int, int)
    sinyal_log      = pyqtSignal(str)
    sinyal_chunk    = pyqtSignal(int, int, bytes)
    sinyal_info     = pyqtSignal(int, int, int)
    sinyal_bitti    = pyqtSignal(int, bool)

    def __init__(self, port_idx: int, port_adi: str, baud: int,
                 tek_port: bool = False):
        super().__init__()
        self.port_idx  = port_idx
        self.port_adi  = port_adi
        self.baud      = baud
        self.tek_port  = tek_port
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
            self.sinyal_log.emit(f"[COM{pi+1}] Open failed: {e}")
            self.sinyal_bitti.emit(pi, False)
            return

        try:
            self.basarili = self._al(ser)
        except Exception as e:
            self.sinyal_log.emit(f"[COM{pi+1}] Unexpected error: {e}")
            self.basarili = False
        finally:
            ser.close()

        self.sinyal_bitti.emit(pi, self.basarili)

    def _al(self, ser: serial.Serial) -> bool:
        pi = self.port_idx

        self.sinyal_log.emit(f"[COM{pi+1}] Awaiting sender (sending READY)...")
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
                    self.sinyal_log.emit(f"[COM{pi+1}] ABORT received")
                    return False
                self.sinyal_log.emit(f"[COM{pi+1}] Awaiting INFO, got type: {tip:#x} (ignored)")
            except TimeoutError:
                continue
        if info_veri is None:
            self.sinyal_log.emit(f"[COM{pi+1}] INFO packet timeout")
            return False
        veri = info_veri

        toplam_chunk, zip_boyutu = struct.unpack('>IQ', veri[:12])
        self.sinyal_log.emit(
            f"[COM{pi+1}] Link info: {toplam_chunk} packets, {zip_boyutu:,} bytes"
        )
        self.sinyal_info.emit(pi, toplam_chunk, zip_boyutu)

        if self.tek_port:
            self._benim_toplam = toplam_chunk
        else:
            self._benim_toplam = (toplam_chunk + (1 - pi)) // 2

        ser.write(paket_olustur(PKT_ACK, 0))

        alinan = 0
        while not self._dur:
            try:
                tip, seq, veri = paket_oku(ser, 60.0)
            except TimeoutError as e:
                self.sinyal_log.emit(f"[COM{pi+1}] {e}")
                return False

            if tip == PKT_EOF:
                self.sinyal_log.emit(f"[COM{pi+1}] EOF — {alinan} packets received")
                break
            elif tip == PKT_ABORT:
                self.sinyal_log.emit(f"[COM{pi+1}] Aborted by remote")
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
    sinyal_genel    = pyqtSignal(int)
    sinyal_port     = pyqtSignal(int, int)
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
        self._threadler: List[PortGonderThread] = []

    def dur(self):
        for t in self._threadler:
            t.dur()

    def run(self):
        self.sinyal_log.emit("Compressing payload...")
        try:
            zip_verisi = zip_olustur(self.ogeler, self.sifre)
        except Exception as e:
            self.sinyal_bitti.emit(False, f"Compression error: {e}")
            return

        n = len(zip_verisi)
        self.sinyal_log.emit(f"Payload ready: {n:,} bytes")

        tum_chunklar: List[Tuple[int, bytes]] = []
        for i, offset in enumerate(range(0, n, self.chunk_boyutu)):
            tum_chunklar.append((i, zip_verisi[offset:offset + self.chunk_boyutu]))

        toplam = len(tum_chunklar)

        if self.tek_port:
            self.sinyal_log.emit(f"Framing {toplam} packets → COM1: {toplam} [single]")
            t0 = PortGonderThread(0, self.port1, self.baud1, tum_chunklar, toplam, n)
            t0.sinyal_ilerleme.connect(self._ilerleme_guncelle)
            t0.sinyal_log.connect(self.sinyal_log)
            self._threadler = [t0]
            t0.start()
            t0.wait()
            ok = t0.basarili
        else:
            c0 = [(s, d) for s, d in tum_chunklar if s % 2 == 0]
            c1 = [(s, d) for s, d in tum_chunklar if s % 2 == 1]
            self.sinyal_log.emit(
                f"Framing {toplam} packets → COM1: {len(c0)}, COM2: {len(c1)}"
            )
            bariyer = threading.Barrier(2)
            t0 = PortGonderThread(0, self.port1, self.baud1, c0, toplam, n, bariyer=bariyer)
            t1 = PortGonderThread(1, self.port2, self.baud2, c1, toplam, n, bariyer=bariyer)
            self._threadler = [t0, t1]
            for t in (t0, t1):
                t.sinyal_ilerleme.connect(self._ilerleme_guncelle)
                t.sinyal_log.connect(self.sinyal_log)
            t0.start()
            t1.start()
            t0.wait()
            t1.wait()
            ok = t0.basarili and t1.basarili

        msg = "Transmission complete." if ok else "Transmission failed."
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
        self._threadler: List[PortAlThread] = []

    def dur(self):
        for t in self._threadler:
            t.dur()

    def run(self):
        if self.tek_port:
            t0 = PortAlThread(0, self.port1, self.baud1, tek_port=True)
            t0.sinyal_log.connect(self.sinyal_log)
            t0.sinyal_ilerleme.connect(self.sinyal_port)
            t0.sinyal_chunk.connect(self._chunk_alindi)
            t0.sinyal_info.connect(self._info_alindi)
            self._threadler = [t0]
            t0.start()
            t0.wait()
            ok = t0.basarili
        else:
            t0 = PortAlThread(0, self.port1, self.baud1)
            t1 = PortAlThread(1, self.port2, self.baud2)
            self._threadler = [t0, t1]
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
            self.sinyal_bitti.emit(False, "Reception failed.")
            return

        self.sinyal_log.emit(f"Reassembling {len(self._chunklar)} packets...")
        try:
            zip_verisi = b''.join(
                self._chunklar[i] for i in sorted(self._chunklar)
            )
        except KeyError as e:
            self.sinyal_bitti.emit(False, f"Missing packet: {e}")
            return

        self.sinyal_log.emit(f"Extracting payload ({len(zip_verisi):,} bytes) → {self.hedef_dizin}")
        try:
            os.makedirs(self.hedef_dizin, exist_ok=True)
            zip_ac(zip_verisi, self.sifre, self.hedef_dizin)
            self.sinyal_bitti.emit(
                True, f"Output written to '{self.hedef_dizin}'."
            )
        except Exception as e:
            self.sinyal_bitti.emit(False, f"Extraction error: {e}")

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
                    f"Link info: {toplam} packets, {zip_boyutu:,} bytes"
                )


# ==============================================================================
# CLIPBOARD THREAD'LERI  (onaysiz / fire-and-forget)
# ==============================================================================

CLIP_CHUNK    = 512
CLIP_GECIKME  = 0.003   # paketler arasi kucuk gecikme (alici tamponunu korur)
CLIP_TEKRAR   = 3       # kritik kontrol paketleri (INFO/EOF) tekrar sayisi


class ClipGonderThread(QThread):
    """Pano icerigini zip+sifre ile, alicidan onay beklemeden gonderir."""
    sinyal_log   = pyqtSignal(str)
    sinyal_bitti = pyqtSignal(bool, str)

    def __init__(self, metin: str, sifre: str, port_adi: str, baud: int,
                 chunk_boyutu: int = CLIP_CHUNK):
        super().__init__()
        self.metin        = metin
        self.sifre        = sifre
        self.port_adi     = port_adi
        self.baud         = baud
        self.chunk_boyutu = chunk_boyutu

    def run(self):
        try:
            zip_verisi = clip_zip_olustur(self.metin, self.sifre)
        except Exception as e:
            self.sinyal_bitti.emit(False, f"Compression error: {e}")
            return

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
            self.sinyal_bitti.emit(False, f"Open failed: {e}")
            return

        try:
            n = len(zip_verisi)
            chunklar = [
                zip_verisi[o:o + self.chunk_boyutu]
                for o in range(0, n, self.chunk_boyutu)
            ]
            toplam = len(chunklar)

            info = struct.pack('>IQ', toplam, n)
            for _ in range(CLIP_TEKRAR):
                ser.write(paket_olustur(PKT_CLIP_INFO, 0, info))
                time.sleep(CLIP_GECIKME)

            for i, c in enumerate(chunklar):
                ser.write(paket_olustur(PKT_CLIP_DATA, i, c))
                time.sleep(CLIP_GECIKME)

            for _ in range(CLIP_TEKRAR):
                ser.write(paket_olustur(PKT_CLIP_EOF, 0))
                time.sleep(CLIP_GECIKME)

            ser.flush()
            self.sinyal_bitti.emit(
                True, f"Clipboard sent ({toplam} packets, {n:,} bytes)."
            )
        except Exception as e:
            self.sinyal_bitti.emit(False, f"Send error: {e}")
        finally:
            ser.close()


class ClipDinleThread(QThread):
    """Pano paketlerini surekli dinler; tamamlanan icerigi cozup yayinlar."""
    sinyal_log    = pyqtSignal(str)
    sinyal_alindi = pyqtSignal(str)
    sinyal_durdu  = pyqtSignal()

    def __init__(self, sifre: str, port_adi: str, baud: int):
        super().__init__()
        self.sifre    = sifre
        self.port_adi = port_adi
        self.baud     = baud
        self._dur     = False

    def dur(self):
        self._dur = True

    def run(self):
        try:
            ser = serial.Serial(
                self.port_adi, self.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1, write_timeout=5,
                rtscts=False, dsrdtr=False
            )
            ser.reset_input_buffer()
        except serial.SerialException as e:
            self.sinyal_log.emit(f"Open failed: {e}")
            self.sinyal_durdu.emit()
            return

        self.sinyal_log.emit("Listening for clipboard...")
        chunklar: Dict[int, bytes] = {}
        toplam = 0
        try:
            while not self._dur:
                try:
                    tip, seq, veri = paket_oku(ser, 1.0)
                except TimeoutError:
                    continue

                if tip == PKT_CLIP_INFO and len(veri) >= 12:
                    toplam, beklenen = struct.unpack('>IQ', veri[:12])
                    chunklar = {}
                    self.sinyal_log.emit(
                        f"Incoming clipboard: {toplam} packets, {beklenen:,} bytes"
                    )
                elif tip == PKT_CLIP_DATA:
                    chunklar[seq] = veri
                elif tip == PKT_CLIP_EOF:
                    if toplam == 0:
                        continue
                    if len(chunklar) < toplam:
                        eksik = toplam - len(chunklar)
                        self.sinyal_log.emit(
                            f"Incomplete clipboard: {eksik} packet(s) missing, discarded"
                        )
                    else:
                        try:
                            zip_verisi = b''.join(chunklar[i] for i in range(toplam))
                            metin = clip_zip_ac(zip_verisi, self.sifre)
                            self.sinyal_alindi.emit(metin)
                            self.sinyal_log.emit(
                                f"Clipboard received ({len(metin)} chars) — copied"
                            )
                        except Exception as e:
                            self.sinyal_log.emit(f"Decrypt/extract error: {e}")
                    chunklar = {}
                    toplam = 0
        finally:
            ser.close()
        self.sinyal_durdu.emit()


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
        yenile_btn.setToolTip("Refresh ports")
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
    lbl.setFont(QFont('Courier New', 9))
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setValue(0)
    bar.setTextVisible(True)
    satir.addWidget(lbl)
    satir.addWidget(bar)
    ana_duzen.addLayout(satir)
    return bar


# ==============================================================================
# TX SEKMESI
# ==============================================================================

class GonderSekmesi(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._yonetici: Optional[GonderYoneticisi] = None
        self._ui_olustur()

    def _ui_olustur(self):
        ana = QVBoxLayout(self)
        ana.setSpacing(8)

        # --- Source payload ---
        dosya_grup = QGroupBox("Source Payload")
        dg = QVBoxLayout(dosya_grup)

        self.dosya_listesi = QListWidget()
        self.dosya_listesi.setMinimumHeight(110)
        self.dosya_listesi.setAlternatingRowColors(True)
        self.dosya_listesi.setFont(QFont('Courier New', 9))
        dg.addWidget(self.dosya_listesi)

        btn_satir = QHBoxLayout()
        for metin, slot in [
            ("+ File", self._dosya_ekle),
            ("+ Dir",  self._dizin_ekle),
            ("Remove", self._kaldir),
            ("Clear",  self.dosya_listesi.clear),
        ]:
            b = QPushButton(metin)
            b.clicked.connect(slot)
            btn_satir.addWidget(b)
        dg.addLayout(btn_satir)
        ana.addWidget(dosya_grup)

        # --- Port mode ---
        mod_satir = QHBoxLayout()
        self.tek_port_cb = QCheckBox("Single Port  [COM1 only]")
        self.tek_port_cb.toggled.connect(self._tek_port_guncelle)
        mod_satir.addWidget(self.tek_port_cb)
        mod_satir.addStretch()
        ana.addLayout(mod_satir)

        # --- Port settings ---
        port_satir = QHBoxLayout()
        self.port1 = PortSeciciWidget("COM1  [even: 0,2,4...]")
        self.port2 = PortSeciciWidget("COM2  [odd: 1,3,5...]")
        port_satir.addWidget(self.port1)
        port_satir.addWidget(self.port2)
        ana.addLayout(port_satir)

        # --- Key + packet size ---
        opt_satir = QHBoxLayout()

        sifre_grup = QGroupBox("Encryption Key")
        sg = QHBoxLayout(sifre_grup)
        self.sifre_giris = QLineEdit()
        self.sifre_giris.setEchoMode(QLineEdit.Password)
        self.sifre_giris.setPlaceholderText("key...")
        self.sifre_giris.setFont(QFont('Courier New', 9))
        sg.addWidget(self.sifre_giris)
        self.sifre_goster = QCheckBox("Show")
        self.sifre_goster.toggled.connect(
            lambda c: self.sifre_giris.setEchoMode(
                QLineEdit.Normal if c else QLineEdit.Password
            )
        )
        sg.addWidget(self.sifre_goster)
        opt_satir.addWidget(sifre_grup, 3)

        chunk_grup = QGroupBox("Packet Size")
        cg = QHBoxLayout(chunk_grup)
        self.chunk_combo = QComboBox()
        for c in CHUNK_BOYUTLARI:
            self.chunk_combo.addItem(f"{c} B")
        self.chunk_combo.setCurrentText("512 B")
        cg.addWidget(self.chunk_combo)
        opt_satir.addWidget(chunk_grup, 1)

        ana.addLayout(opt_satir)

        # --- Progress bars ---
        ilerleme_grup = QGroupBox("Link Status")
        ig = QVBoxLayout(ilerleme_grup)
        self.bar_port1 = ilerleme_satiri_olustur("COM1:", ig)
        self.bar_port2 = ilerleme_satiri_olustur("COM2:", ig)
        self.bar_genel = ilerleme_satiri_olustur("Total:", ig)
        ana.addWidget(ilerleme_grup)

        # --- Console output ---
        log_grup = QGroupBox("Console Output")
        lg = QVBoxLayout(log_grup)
        self.log = LogAlani()
        lg.addWidget(self.log)
        ana.addWidget(log_grup)

        # --- Action buttons ---
        btn_satir2 = QHBoxLayout()
        self.btn_gonder = QPushButton("TRANSMIT")
        self.btn_gonder.setFixedHeight(42)
        self.btn_gonder.setFont(QFont('Courier New', 11, QFont.Bold))
        self.btn_gonder.clicked.connect(self._gonderi_baslat)
        btn_satir2.addWidget(self.btn_gonder)

        self.btn_iptal = QPushButton("ABORT")
        self.btn_iptal.setFixedHeight(42)
        self.btn_iptal.setFixedWidth(110)
        self.btn_iptal.setFont(QFont('Courier New', 11, QFont.Bold))
        self.btn_iptal.setEnabled(False)
        self.btn_iptal.clicked.connect(self._iptal)
        btn_satir2.addWidget(self.btn_iptal)
        ana.addLayout(btn_satir2)

    def _tek_port_guncelle(self, tek: bool):
        self.port2.setEnabled(not tek)
        self.bar_port2.setEnabled(not tek)
        if tek:
            self.bar_port2.setValue(0)
        self.port1.setTitle(
            "COM1" if tek else "COM1  [even: 0,2,4...]"
        )

    def _dosya_ekle(self):
        dosyalar, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for d in dosyalar:
            if not self._listede_mi(d):
                self.dosya_listesi.addItem(QListWidgetItem(d))

    def _dizin_ekle(self):
        d = QFileDialog.getExistingDirectory(self, "Select Directory")
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

    def _iptal(self):
        if self._yonetici and self._yonetici.isRunning():
            self._yonetici.dur()
            self.btn_iptal.setEnabled(False)
            self.log.log_ekle("Abort requested...")

    def _gonderi_baslat(self):
        ogeler = self._ogeler()
        if not ogeler:
            QMessageBox.warning(self, "Warning", "No source payload selected.")
            return

        sifre = self.sifre_giris.text()
        if not sifre:
            QMessageBox.warning(self, "Warning", "Encryption key required.")
            return

        tek_port = self.tek_port_cb.isChecked()
        p1 = self.port1.port
        p2 = self.port2.port
        if not p1:
            QMessageBox.warning(self, "Warning", "COM1 not selected.")
            return
        if not tek_port:
            if not p2:
                QMessageBox.warning(self, "Warning", "COM2 not selected.")
                return
            if p1 == p2:
                QMessageBox.warning(self, "Warning", "COM1 and COM2 must differ.")
                return

        self.btn_gonder.setEnabled(False)
        self.btn_iptal.setEnabled(True)
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
        self.btn_iptal.setEnabled(False)
        self.log.log_ekle(mesaj)
        if ok:
            for bar in (self.bar_port1, self.bar_port2, self.bar_genel):
                bar.setValue(100)
            QMessageBox.information(self, "OK", mesaj)
        else:
            QMessageBox.critical(self, "Error", mesaj)


# ==============================================================================
# RX SEKMESI
# ==============================================================================

class AlSekmesi(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._yonetici: Optional[AlYoneticisi] = None
        self._ui_olustur()

    def _ui_olustur(self):
        ana = QVBoxLayout(self)
        ana.setSpacing(8)

        # --- Output path ---
        cikti_grup = QGroupBox("Output Path")
        cg = QHBoxLayout(cikti_grup)
        self.cikti_giris = QLineEdit()
        self.cikti_giris.setPlaceholderText("output directory...")
        self.cikti_giris.setFont(QFont('Courier New', 9))
        cg.addWidget(self.cikti_giris)
        gozat_btn = QPushButton("Browse...")
        gozat_btn.clicked.connect(self._cikti_sec)
        cg.addWidget(gozat_btn)
        ana.addWidget(cikti_grup)

        # --- Port mode ---
        mod_satir = QHBoxLayout()
        self.tek_port_cb = QCheckBox("Single Port  [COM1 only]")
        self.tek_port_cb.toggled.connect(self._tek_port_guncelle)
        mod_satir.addWidget(self.tek_port_cb)
        mod_satir.addStretch()
        ana.addLayout(mod_satir)

        # --- Port settings ---
        port_satir = QHBoxLayout()
        self.port1 = PortSeciciWidget("COM1")
        self.port2 = PortSeciciWidget("COM2")
        port_satir.addWidget(self.port1)
        port_satir.addWidget(self.port2)
        ana.addLayout(port_satir)

        # --- Decryption key ---
        sifre_grup = QGroupBox("Decryption Key")
        sg = QHBoxLayout(sifre_grup)
        self.sifre_giris = QLineEdit()
        self.sifre_giris.setEchoMode(QLineEdit.Password)
        self.sifre_giris.setPlaceholderText("key...")
        self.sifre_giris.setFont(QFont('Courier New', 9))
        sg.addWidget(self.sifre_giris)
        self.sifre_goster = QCheckBox("Show")
        self.sifre_goster.toggled.connect(
            lambda c: self.sifre_giris.setEchoMode(
                QLineEdit.Normal if c else QLineEdit.Password
            )
        )
        sg.addWidget(self.sifre_goster)
        ana.addWidget(sifre_grup)

        # --- Progress bars ---
        ilerleme_grup = QGroupBox("Link Status")
        ig = QVBoxLayout(ilerleme_grup)
        self.bar_port1 = ilerleme_satiri_olustur("COM1:", ig)
        self.bar_port2 = ilerleme_satiri_olustur("COM2:", ig)
        self.bar_genel = ilerleme_satiri_olustur("Total:", ig)
        ana.addWidget(ilerleme_grup)

        # --- Console output ---
        log_grup = QGroupBox("Console Output")
        lg = QVBoxLayout(log_grup)
        self.log = LogAlani()
        lg.addWidget(self.log)
        ana.addWidget(log_grup)

        # --- Action buttons ---
        btn_satir = QHBoxLayout()
        self.btn_al = QPushButton("RECEIVE")
        self.btn_al.setFixedHeight(42)
        self.btn_al.setFont(QFont('Courier New', 11, QFont.Bold))
        self.btn_al.clicked.connect(self._alimi_baslat)
        btn_satir.addWidget(self.btn_al)

        self.btn_iptal = QPushButton("ABORT")
        self.btn_iptal.setFixedHeight(42)
        self.btn_iptal.setFixedWidth(110)
        self.btn_iptal.setFont(QFont('Courier New', 11, QFont.Bold))
        self.btn_iptal.setEnabled(False)
        self.btn_iptal.clicked.connect(self._iptal)
        btn_satir.addWidget(self.btn_iptal)
        ana.addLayout(btn_satir)

    def _tek_port_guncelle(self, tek: bool):
        self.port2.setEnabled(not tek)
        self.bar_port2.setEnabled(not tek)
        if tek:
            self.bar_port2.setValue(0)

    def _cikti_sec(self):
        d = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if d:
            self.cikti_giris.setText(d)

    def _iptal(self):
        if self._yonetici and self._yonetici.isRunning():
            self._yonetici.dur()
            self.btn_iptal.setEnabled(False)
            self.log.log_ekle("Abort requested...")

    def _alimi_baslat(self):
        cikti = self.cikti_giris.text().strip()
        if not cikti:
            QMessageBox.warning(self, "Warning", "Output path not specified.")
            return

        sifre = self.sifre_giris.text()
        if not sifre:
            QMessageBox.warning(self, "Warning", "Decryption key required.")
            return

        tek_port = self.tek_port_cb.isChecked()
        p1 = self.port1.port
        p2 = self.port2.port
        if not p1:
            QMessageBox.warning(self, "Warning", "COM1 not selected.")
            return
        if not tek_port:
            if not p2:
                QMessageBox.warning(self, "Warning", "COM2 not selected.")
                return
            if p1 == p2:
                QMessageBox.warning(self, "Warning", "COM1 and COM2 must differ.")
                return

        self.btn_al.setEnabled(False)
        self.btn_iptal.setEnabled(True)
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
        self.btn_iptal.setEnabled(False)
        self.log.log_ekle(mesaj)
        if ok:
            for bar in (self.bar_port1, self.bar_port2, self.bar_genel):
                bar.setValue(100)
            QMessageBox.information(self, "OK", mesaj)
        else:
            QMessageBox.critical(self, "Error", mesaj)


# ==============================================================================
# CLIP SEKMESI
# ==============================================================================

class ClipSekmesi(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._gonder_thread: Optional[ClipGonderThread] = None
        self._dinle_thread: Optional[ClipDinleThread] = None
        self._ui_olustur()

    def _ui_olustur(self):
        ana = QVBoxLayout(self)
        ana.setSpacing(8)

        # --- Port settings (single port) ---
        port_satir = QHBoxLayout()
        self.port1 = PortSeciciWidget("COM Port")
        port_satir.addWidget(self.port1)
        ana.addLayout(port_satir)

        # --- Encryption key ---
        sifre_grup = QGroupBox("Encryption Key")
        sg = QHBoxLayout(sifre_grup)
        self.sifre_giris = QLineEdit()
        self.sifre_giris.setEchoMode(QLineEdit.Password)
        self.sifre_giris.setPlaceholderText("key...")
        self.sifre_giris.setFont(QFont('Courier New', 9))
        sg.addWidget(self.sifre_giris)
        self.sifre_goster = QCheckBox("Show")
        self.sifre_goster.toggled.connect(
            lambda c: self.sifre_giris.setEchoMode(
                QLineEdit.Normal if c else QLineEdit.Password
            )
        )
        sg.addWidget(self.sifre_goster)
        ana.addWidget(sifre_grup)

        # --- Clipboard preview (no files touched) ---
        onizleme_grup = QGroupBox("Clipboard Content")
        og = QVBoxLayout(onizleme_grup)
        self.onizleme = QTextEdit()
        self.onizleme.setReadOnly(True)
        self.onizleme.setFont(QFont('Courier New', 9))
        self.onizleme.setMinimumHeight(140)
        self.onizleme.setPlaceholderText(
            "Sent / received clipboard text shown here..."
        )
        og.addWidget(self.onizleme)
        ana.addWidget(onizleme_grup)

        # --- Console output ---
        log_grup = QGroupBox("Console Output")
        lg = QVBoxLayout(log_grup)
        self.log = LogAlani()
        lg.addWidget(self.log)
        ana.addWidget(log_grup)

        # --- Action buttons ---
        btn_satir = QHBoxLayout()
        self.btn_gonder = QPushButton("SEND CLIPBOARD")
        self.btn_gonder.setFixedHeight(42)
        self.btn_gonder.setFont(QFont('Courier New', 11, QFont.Bold))
        self.btn_gonder.clicked.connect(self._gonder)
        btn_satir.addWidget(self.btn_gonder)

        self.btn_dinle = QPushButton("LISTEN")
        self.btn_dinle.setFixedHeight(42)
        self.btn_dinle.setFixedWidth(140)
        self.btn_dinle.setFont(QFont('Courier New', 11, QFont.Bold))
        self.btn_dinle.setCheckable(True)
        self.btn_dinle.clicked.connect(self._dinle_toggle)
        btn_satir.addWidget(self.btn_dinle)
        ana.addLayout(btn_satir)

    # --- Send ---

    def _gonder(self):
        sifre = self.sifre_giris.text()
        if not sifre:
            QMessageBox.warning(self, "Warning", "Encryption key required.")
            return
        p1 = self.port1.port
        if not p1:
            QMessageBox.warning(self, "Warning", "COM port not selected.")
            return

        metin = QApplication.clipboard().text()
        if not metin:
            QMessageBox.warning(self, "Warning", "System clipboard is empty.")
            return

        self.onizleme.setPlainText(metin)
        self.btn_gonder.setEnabled(False)
        self.log.log_ekle(f"Sending clipboard ({len(metin)} chars)...")

        self._gonder_thread = ClipGonderThread(
            metin, sifre, p1, self.port1.baud
        )
        self._gonder_thread.sinyal_log.connect(self.log.log_ekle)
        self._gonder_thread.sinyal_bitti.connect(self._gonder_bitti)
        self._gonder_thread.start()

    def _gonder_bitti(self, ok: bool, mesaj: str):
        self.btn_gonder.setEnabled(True)
        self.log.log_ekle(mesaj)
        if not ok:
            QMessageBox.critical(self, "Error", mesaj)

    # --- Listen / Receive ---

    def _dinle_toggle(self):
        if self._dinle_thread and self._dinle_thread.isRunning():
            self.btn_dinle.setEnabled(False)
            self.log.log_ekle("Stopping listener...")
            self._dinle_thread.dur()
            return

        sifre = self.sifre_giris.text()
        if not sifre:
            QMessageBox.warning(self, "Warning", "Encryption key required.")
            self.btn_dinle.setChecked(False)
            return
        p1 = self.port1.port
        if not p1:
            QMessageBox.warning(self, "Warning", "COM port not selected.")
            self.btn_dinle.setChecked(False)
            return

        self.btn_dinle.setText("STOP")
        self.btn_dinle.setChecked(True)
        self.btn_gonder.setEnabled(False)
        self.port1.setEnabled(False)

        self._dinle_thread = ClipDinleThread(sifre, p1, self.port1.baud)
        self._dinle_thread.sinyal_log.connect(self.log.log_ekle)
        self._dinle_thread.sinyal_alindi.connect(self._alindi)
        self._dinle_thread.sinyal_durdu.connect(self._dinle_durdu)
        self._dinle_thread.start()

    def _alindi(self, metin: str):
        QApplication.clipboard().setText(metin)
        self.onizleme.setPlainText(metin)

    def _dinle_durdu(self):
        self.btn_dinle.setEnabled(True)
        self.btn_dinle.setChecked(False)
        self.btn_dinle.setText("LISTEN")
        self.btn_gonder.setEnabled(True)
        self.port1.setEnabled(True)
        self.log.log_ekle("Listener stopped.")


# ==============================================================================
# ANA PENCERE
# ==============================================================================

class AnaPencere(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RS232 Serial Link Terminal")
        self.setMinimumSize(820, 680)

        merkez = QWidget()
        self.setCentralWidget(merkez)
        ana = QVBoxLayout(merkez)
        ana.setContentsMargins(10, 10, 10, 10)
        ana.setSpacing(8)

        baslik = QLabel("RS232 Serial Link Terminal")
        baslik.setFont(QFont('Courier New', 13, QFont.Bold))
        baslik.setAlignment(Qt.AlignCenter)
        ana.addWidget(baslik)

        ayrac = QFrame()
        ayrac.setFrameShape(QFrame.HLine)
        ayrac.setFrameShadow(QFrame.Sunken)
        ana.addWidget(ayrac)

        sekmeler = QTabWidget()
        sekmeler.addTab(GonderSekmesi(), "  [ TX ]  ")
        sekmeler.addTab(AlSekmesi(),     "  [ RX ]  ")
        sekmeler.addTab(ClipSekmesi(),   "  [ CLIP ]  ")
        sekmeler.setFont(QFont('Courier New', 10))
        ana.addWidget(sekmeler)

        self.statusBar().showMessage(
            "IDLE  |  Ensure matching baud rate and key on both endpoints."
        )


# ==============================================================================
# TEMA
# ==============================================================================

def koyu_tema_uygula(uygulama: QApplication):
    uygulama.setStyle('Fusion')
    palet = QPalette()
    renk = {
        QPalette.Window:          QColor(18,  18,  18),
        QPalette.WindowText:      QColor(180, 255, 180),
        QPalette.Base:            QColor(10,  10,  10),
        QPalette.AlternateBase:   QColor(22,  22,  22),
        QPalette.ToolTipBase:     QColor(22,  22,  22),
        QPalette.ToolTipText:     QColor(180, 255, 180),
        QPalette.Text:            QColor(180, 255, 180),
        QPalette.Button:          QColor(30,  30,  30),
        QPalette.ButtonText:      QColor(180, 255, 180),
        QPalette.BrightText:      QColor(255,  80,  80),
        QPalette.Link:            QColor(0,   200, 100),
        QPalette.Highlight:       QColor(0,   160,  80),
        QPalette.HighlightedText: QColor(0,   0,   0),
        QPalette.Disabled + QPalette.Text:       QColor(80,  80,  80),
        QPalette.Disabled + QPalette.ButtonText: QColor(80,  80,  80),
    }
    for rol, renk_degeri in renk.items():
        palet.setColor(rol, renk_degeri)
    uygulama.setPalette(palet)

    uygulama.setStyleSheet("""
        QProgressBar {
            border: 1px solid #2a5a2a;
            border-radius: 2px;
            text-align: center;
            background: #0a120a;
            color: #b4ffb4;
            font-family: 'Courier New';
            font-size: 9pt;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #0a6a0a, stop:1 #00c850);
            border-radius: 1px;
        }
        QGroupBox {
            font-family: 'Courier New';
            font-weight: bold;
            font-size: 9pt;
            border: 1px solid #2a5a2a;
            border-radius: 3px;
            margin-top: 8px;
            padding-top: 4px;
            color: #80ff80;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 4px;
        }
        QPushButton {
            font-family: 'Courier New';
            border: 1px solid #2a5a2a;
            border-radius: 2px;
            padding: 4px 10px;
            background: #0e1e0e;
            color: #b4ffb4;
        }
        QPushButton:hover   { background: #1a3a1a; border-color: #40a040; }
        QPushButton:pressed { background: #005500; }
        QPushButton:disabled { color: #3a5a3a; border-color: #1a3a1a; }
        QTabBar::tab {
            font-family: 'Courier New';
            font-size: 10pt;
            padding: 6px 16px;
            background: #0e1e0e;
            border: 1px solid #2a5a2a;
            border-bottom: none;
            border-top-left-radius: 3px;
            border-top-right-radius: 3px;
            color: #80c080;
        }
        QTabBar::tab:selected { background: #005500; color: #b4ffb4; }
        QTabBar::tab:hover:!selected { background: #1a3a1a; }
        QListWidget {
            border: 1px solid #2a5a2a;
            border-radius: 2px;
            background: #0a0a0a;
            color: #b4ffb4;
            font-family: 'Courier New';
            font-size: 9pt;
        }
        QLineEdit {
            font-family: 'Courier New';
            border: 1px solid #2a5a2a;
            border-radius: 2px;
            padding: 3px 6px;
            background: #0a0a0a;
            color: #b4ffb4;
        }
        QComboBox {
            font-family: 'Courier New';
            border: 1px solid #2a5a2a;
            border-radius: 2px;
            padding: 3px 6px;
            background: #0a0a0a;
            color: #b4ffb4;
        }
        QComboBox::drop-down { border: none; }
        QComboBox QAbstractItemView {
            background: #0a120a;
            color: #b4ffb4;
            selection-background-color: #005500;
        }
        QTextEdit {
            border: 1px solid #2a5a2a;
            border-radius: 2px;
            background: #020802;
            color: #00e000;
            font-family: 'Courier New';
        }
        QCheckBox {
            font-family: 'Courier New';
            color: #b4ffb4;
        }
        QLabel {
            font-family: 'Courier New';
            color: #b4ffb4;
        }
        QStatusBar {
            font-family: 'Courier New';
            font-size: 9pt;
            color: #608060;
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
