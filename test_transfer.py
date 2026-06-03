#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rs232_transfer.py icin birim ve entegrasyon testleri.
Gercek COM portu gerektirmez — Queue tabanli sahte seri port kullanir.
"""

import os
import sys
import queue
import struct
import threading
import tempfile
import time
import zlib
import unittest

# PyQt5 uygulamasini en basta baslat (QThread icin gerekli)
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

_app = QApplication.instance() or QApplication(sys.argv)

# Test edilen modulu import et
sys.path.insert(0, os.path.dirname(__file__))
from rs232_transfer import (
    MAGIC, PKT_READY, PKT_INFO, PKT_DATA, PKT_EOF, PKT_ACK, PKT_NAK,
    HDR_FMT, HDR_SIZE, VARSAYILAN_CHUNK,
    paket_olustur, paket_oku,
    zip_olustur, zip_ac,
    PortGonderThread, PortAlThread,
)

# ==============================================================================
# SAHTE SERI PORT  (Queue tabanli — platformdan bagimsiz, guvenilir)
# ==============================================================================

class SahtePort:
    """
    threading.Queue uzerinden seri port arabirimi simule eder.
    serial.Serial ile ayni in_waiting / read / write / close API'sini saglar.
    """

    def __init__(self, rx_q: queue.Queue, tx_q: queue.Queue, timeout: float = 1.0):
        self._rx       = rx_q
        self._tx       = tx_q
        self._timeout  = timeout
        self._buf      = b''    # local byte buffer

    @property
    def in_waiting(self) -> int:
        """Yerel tamponda bekleme kac byte var."""
        return len(self._buf)

    def read(self, n: int) -> bytes:
        # Tampon bos ise kuyrudan doldur
        if not self._buf:
            try:
                chunk = self._rx.get(timeout=self._timeout)
                self._buf += chunk
            except queue.Empty:
                return b''

        result    = self._buf[:n]
        self._buf = self._buf[n:]
        return result

    def write(self, data: bytes) -> int:
        self._tx.put(bytes(data))
        return len(data)

    def close(self):
        pass   # Queue'nun kapatilmasina gerek yok

    def flush(self):
        pass


def port_cifti_olustur(timeout: float = 2.0):
    """
    Birbirine bagli iki SahtePort dondurur.
    a.write(x) → b.read() == x
    b.write(y) → a.read() == y
    """
    q_ab = queue.Queue()   # a → b
    q_ba = queue.Queue()   # b → a
    return (SahtePort(q_ba, q_ab, timeout),
            SahtePort(q_ab, q_ba, timeout))


# ==============================================================================
# SAHTE THREAD'LER  (serial.Serial yerine SahtePort kullanan)
# ==============================================================================

class SahteGonderThread(PortGonderThread):
    def __init__(self, *args, sahte_ser: SahtePort, **kwargs):
        super().__init__(*args, **kwargs)
        self._sahte_ser = sahte_ser

    def run(self):
        pi = self.port_idx
        try:
            self.basarili = self._gonder(self._sahte_ser)
        except Exception as e:
            self.sinyal_log.emit(f"[Port{pi+1}] Hata: {e}")
            self.basarili = False
        self.sinyal_bitti.emit(pi, self.basarili)


class SahteAlThread(PortAlThread):
    def __init__(self, *args, sahte_ser: SahtePort, **kwargs):
        super().__init__(*args, **kwargs)
        self._sahte_ser = sahte_ser

    def run(self):
        pi = self.port_idx
        try:
            self.basarili = self._al(self._sahte_ser)
        except Exception as e:
            self.sinyal_log.emit(f"[Port{pi+1}] Hata: {e}")
            self.basarili = False
        self.sinyal_bitti.emit(pi, self.basarili)


# ==============================================================================
# 1. PROTOKOL BIRIM TESTLERI
# ==============================================================================

class ProtokolTestleri(unittest.TestCase):

    def test_paket_boyutu(self):
        """Paket boyutu = HDR + veri + CRC4."""
        veri = b'Merhaba'
        pkt  = paket_olustur(PKT_DATA, 7, veri)
        self.assertEqual(len(pkt), HDR_SIZE + len(veri) + 4)

    def test_magic_basi(self):
        pkt = paket_olustur(PKT_ACK, 0)
        self.assertTrue(pkt.startswith(MAGIC))

    def test_crc_dogru(self):
        veri = b'test verisi'
        pkt  = paket_olustur(PKT_DATA, 3, veri)
        govde     = pkt[:HDR_SIZE + len(veri)]
        crc_hesap = zlib.crc32(govde) & 0xFFFFFFFF
        crc_paket = struct.unpack('>I', pkt[-4:])[0]
        self.assertEqual(crc_hesap, crc_paket)

    def test_tek_paket_tur(self):
        """Olustur → gonder → oku tam turu."""
        a, b = port_cifti_olustur()
        a.write(paket_olustur(PKT_DATA, 42, b'paralel transfer'))
        tip, seq, alinan = paket_oku(b, bekleme=3.0)
        self.assertEqual(tip, PKT_DATA)
        self.assertEqual(seq, 42)
        self.assertEqual(alinan, b'paralel transfer')

    def test_bozuk_bayt_atlaniyor(self):
        """Once cop, sonra gecerli paket; sadece gecerli paket okunmali."""
        a, b = port_cifti_olustur()
        a.write(b'\x00\xFF\xAB\xCD bozuk bozuk bozuk')
        a.write(paket_olustur(PKT_ACK, 99))
        tip, seq, _ = paket_oku(b, bekleme=5.0)
        self.assertEqual(tip, PKT_ACK)
        self.assertEqual(seq, 99)

    def test_bos_veri_paketi(self):
        a, b = port_cifti_olustur()
        a.write(paket_olustur(PKT_EOF, 0))
        tip, seq, veri = paket_oku(b, bekleme=3.0)
        self.assertEqual(tip, PKT_EOF)
        self.assertEqual(veri, b'')

    def test_ardisik_10_paket(self):
        """10 paketi arka arkaya gonder, sirayla oku."""
        a, b = port_cifti_olustur(timeout=3.0)
        N = 10
        for i in range(N):
            a.write(paket_olustur(PKT_DATA, i, f'chunk-{i}'.encode()))
        for i in range(N):
            tip, seq, veri = paket_oku(b, bekleme=5.0)
            self.assertEqual(tip, PKT_DATA)
            self.assertEqual(seq, i)
            self.assertEqual(veri, f'chunk-{i}'.encode())

    def test_timeout_firlatir(self):
        """Veri gelmediginde TimeoutError firlatmali."""
        _, b = port_cifti_olustur(timeout=0.1)
        with self.assertRaises(TimeoutError):
            paket_oku(b, bekleme=0.3)

    def test_buyuk_chunk(self):
        """4096 baytlik chunk encode/decode."""
        a, b = port_cifti_olustur(timeout=3.0)
        veri = os.urandom(4096)
        a.write(paket_olustur(PKT_DATA, 0, veri))
        tip, seq, alinan = paket_oku(b, bekleme=5.0)
        self.assertEqual(alinan, veri)

    def test_birden_fazla_boyut(self):
        """Farkli boyutlarda paketler art arda."""
        a, b = port_cifti_olustur(timeout=3.0)
        boyutlar = [0, 1, 127, 128, 255, 512, 1000]
        for i, n in enumerate(boyutlar):
            veri = bytes([i % 256]) * n
            a.write(paket_olustur(PKT_DATA, i, veri))
        for i, n in enumerate(boyutlar):
            tip, seq, alinan = paket_oku(b, bekleme=5.0)
            self.assertEqual(seq, i)
            self.assertEqual(len(alinan), n)


# ==============================================================================
# 2. ZIP BIRIM TESTLERI
# ==============================================================================

class ZipTestleri(unittest.TestCase):

    def _kaynak_olustur(self, tmp: str):
        dosya1 = os.path.join(tmp, 'belge.txt')
        with open(dosya1, 'w') as f:
            f.write('Test icerigi.\n' * 200)
        alt = os.path.join(tmp, 'klasor')
        os.makedirs(alt)
        dosya2 = os.path.join(alt, 'veri.bin')
        with open(dosya2, 'wb') as f:
            f.write(os.urandom(4096))
        return dosya1, alt

    def test_dosya_ve_dizin(self):
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            d1, d2 = self._kaynak_olustur(kaynak)
            zb = zip_olustur([d1, d2], 'sifre123')
            self.assertGreater(len(zb), 0)
            zip_ac(zb, 'sifre123', hedef)
            self.assertTrue(os.path.isfile(os.path.join(hedef, 'belge.txt')))
            self.assertTrue(
                os.path.isfile(os.path.join(hedef, 'klasor', 'veri.bin'))
            )

    def test_yanlis_sifre(self):
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            f = os.path.join(kaynak, 'x.txt')
            open(f, 'w').write('x')
            zb = zip_olustur([f], 'dogru')
            with self.assertRaises(Exception):
                zip_ac(zb, 'yanlis', hedef)

    def test_buyuk_dosya(self):
        """5 MB rastgele veri — zip aç, icerik korunsun."""
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            orijinal = os.urandom(5 * 1024 * 1024)
            f = os.path.join(kaynak, 'buyuk.bin')
            with open(f, 'wb') as fp:
                fp.write(orijinal)
            zb = zip_olustur([f], 'sifre')
            zip_ac(zb, 'sifre', hedef)
            geri = open(os.path.join(hedef, 'buyuk.bin'), 'rb').read()
            self.assertEqual(orijinal, geri)

    def test_bos_dosya(self):
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            f = os.path.join(kaynak, 'bos.txt')
            open(f, 'w').close()
            zb = zip_olustur([f], 's')
            zip_ac(zb, 's', hedef)
            self.assertTrue(os.path.isfile(os.path.join(hedef, 'bos.txt')))


# ==============================================================================
# 3. CHUNK BOLME MANTIĞI TESTLERI
# ==============================================================================

class ChunkBolmeTestleri(unittest.TestCase):

    def test_cift_tek_dagilim_10(self):
        c0 = [i for i in range(10) if i % 2 == 0]
        c1 = [i for i in range(10) if i % 2 == 1]
        self.assertEqual(c0, [0, 2, 4, 6, 8])
        self.assertEqual(c1, [1, 3, 5, 7, 9])
        self.assertEqual(sorted(c0 + c1), list(range(10)))

    def test_tek_chunk(self):
        c0 = [i for i in range(1) if i % 2 == 0]
        c1 = [i for i in range(1) if i % 2 == 1]
        self.assertEqual(c0, [0])
        self.assertEqual(c1, [])

    def test_iki_chunk(self):
        c0 = [i for i in range(2) if i % 2 == 0]
        c1 = [i for i in range(2) if i % 2 == 1]
        self.assertEqual(c0, [0])
        self.assertEqual(c1, [1])

    def test_yeniden_birlestirme(self):
        """Bolunmus ve karistirilan chunklar dogru siraya donebilmeli."""
        orijinal = list(range(20))
        c0 = [(i, i) for i in orijinal if i % 2 == 0]
        c1 = [(i, i) for i in orijinal if i % 2 == 1]
        hepsi = dict(c0 + c1)
        geri  = [hepsi[i] for i in sorted(hepsi)]
        self.assertEqual(geri, orijinal)


# ==============================================================================
# 4. UCTAN-UCA ENTEGRASYON TESTLERI
# ==============================================================================

class EntegrasyonTestleri(unittest.TestCase):
    """
    Gercek seri port olmadan, SahtePort uzerinden tam transfer testi.
    Gonder ve al thread'leri es zamanli calisir.
    """

    def _cift_port_transfer(self, zip_verisi: bytes, chunk_boyutu: int):
        """
        zip_verisi'ni iki sahte port uzerinden gonder, alinan chunklari dondur.
        """
        n      = len(zip_verisi)
        tum    = [(i, zip_verisi[o:o + chunk_boyutu])
                  for i, o in enumerate(range(0, n, chunk_boyutu))]
        toplam = len(tum)
        c0     = [(s, d) for s, d in tum if s % 2 == 0]
        c1     = [(s, d) for s, d in tum if s % 2 == 1]

        g0, a0 = port_cifti_olustur(timeout=5.0)
        g1, a1 = port_cifti_olustur(timeout=5.0)

        alinan: dict = {}
        kilit = threading.Lock()

        def chunk_topla(pi, seq, veri):
            with kilit:
                alinan[seq] = veri

        gt0 = SahteGonderThread(0, '', 0, c0, toplam, n, sahte_ser=g0)
        gt1 = SahteGonderThread(1, '', 0, c1, toplam, n, sahte_ser=g1)
        at0 = SahteAlThread(0, '', 0, sahte_ser=a0)
        at1 = SahteAlThread(1, '', 0, sahte_ser=a1)

        # DirectConnection: sinyali dogrudan emitting thread'de isle
        at0.sinyal_chunk.connect(chunk_topla, Qt.DirectConnection)
        at1.sinyal_chunk.connect(chunk_topla, Qt.DirectConnection)

        mesajlar = []
        for t in (gt0, gt1, at0, at1):
            t.sinyal_log.connect(
                lambda m: mesajlar.append(m), Qt.DirectConnection
            )

        at0.start(); at1.start()
        gt0.start(); gt1.start()

        gt0.wait(60_000); gt1.wait(60_000)
        at0.wait(60_000); at1.wait(60_000)

        return gt0, gt1, at0, at1, alinan, mesajlar

    # ------------------------------------------------------------------ #

    def test_kucuk_dosya_256b_chunk(self):
        """256 bayt zip, 64B chunk — tum chunklar gelsin."""
        SIFRE = 'abc'
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            f = os.path.join(kaynak, 'kucuk.txt')
            orijinal = b'Kucuk test ' * 20
            open(f, 'wb').write(orijinal)
            zip_verisi = zip_olustur([f], SIFRE)

            gt0, gt1, at0, at1, alinan, mesajlar = \
                self._cift_port_transfer(zip_verisi, 64)

            self.assertTrue(gt0.basarili, f"Port0 gonderme hatasi\n{mesajlar}")
            self.assertTrue(gt1.basarili, f"Port1 gonderme hatasi\n{mesajlar}")
            self.assertTrue(at0.basarili, f"Port0 alma hatasi\n{mesajlar}")
            self.assertTrue(at1.basarili, f"Port1 alma hatasi\n{mesajlar}")

            n      = len(zip_verisi)
            toplam = len(list(range(0, n, 64)))
            self.assertEqual(len(alinan), toplam, "Eksik chunk!")

            geri = b''.join(alinan[i] for i in sorted(alinan))
            self.assertEqual(geri, zip_verisi, "ZIP verisi bozuldu!")

            zip_ac(geri, SIFRE, hedef)
            geri_icerik = open(os.path.join(hedef, 'kucuk.txt'), 'rb').read()
            self.assertEqual(orijinal, geri_icerik)

    def test_orta_dosya_512b_chunk(self):
        """~50 KB dosya, 512B chunk."""
        SIFRE = 'guvenli_sifre_2024'
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            f = os.path.join(kaynak, 'orta.bin')
            orijinal = os.urandom(50 * 1024)
            open(f, 'wb').write(orijinal)
            zip_verisi = zip_olustur([f], SIFRE)

            gt0, gt1, at0, at1, alinan, mesajlar = \
                self._cift_port_transfer(zip_verisi, 512)

            for t, isim in [(gt0, 'gt0'), (gt1, 'gt1'),
                             (at0, 'at0'), (at1, 'at1')]:
                self.assertTrue(t.basarili,
                                f"{isim} basarisiz\n" + '\n'.join(mesajlar))

            geri = b''.join(alinan[i] for i in sorted(alinan))
            self.assertEqual(geri, zip_verisi)
            zip_ac(geri, SIFRE, hedef)
            geri_icerik = open(os.path.join(hedef, 'orta.bin'), 'rb').read()
            self.assertEqual(orijinal, geri_icerik,
                             "50KB dosya icerik bozuldu!")
            print(f"\n  [OK] ~50KB dosya, {len(alinan)} chunk ile aktarildi.")

    def test_cok_dosyali_dizin(self):
        """Bir dizin (3 dosya) zip'lenip transfer edilsin."""
        SIFRE = 'klasor_sifre'
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            alt = os.path.join(kaynak, 'proje')
            os.makedirs(alt)
            dosyalar_orijinal = {}
            for ad, boyut in [('a.txt', 1024), ('b.bin', 8192), ('c.dat', 4096)]:
                icerik = os.urandom(boyut)
                dosyalar_orijinal[ad] = icerik
                open(os.path.join(alt, ad), 'wb').write(icerik)

            zip_verisi = zip_olustur([alt], SIFRE)
            gt0, gt1, at0, at1, alinan, mesajlar = \
                self._cift_port_transfer(zip_verisi, 256)

            for t in (gt0, gt1, at0, at1):
                self.assertTrue(t.basarili, '\n'.join(mesajlar))

            geri = b''.join(alinan[i] for i in sorted(alinan))
            zip_ac(geri, SIFRE, hedef)

            for ad, icerik in dosyalar_orijinal.items():
                yol = os.path.join(hedef, 'proje', ad)
                self.assertTrue(os.path.isfile(yol), f"{ad} bulunamadi")
                self.assertEqual(open(yol, 'rb').read(), icerik,
                                 f"{ad} icerigi bozuldu")
            print(f"\n  [OK] 3-dosyali dizin, {len(alinan)} chunk ile aktarildi.")

    def test_tek_chunklik_kucuk_dosya(self):
        """ZIP'i tek porta sigin kadar kucuk dosya."""
        SIFRE = 'x'
        with tempfile.TemporaryDirectory() as kaynak, \
             tempfile.TemporaryDirectory() as hedef:
            f = os.path.join(kaynak, 'mini.txt')
            open(f, 'w').write('hi')
            zip_verisi = zip_olustur([f], SIFRE)
            # chunk boyutu cok buyuk → muhtemelen 1-2 chunk
            gt0, gt1, at0, at1, alinan, mesajlar = \
                self._cift_port_transfer(zip_verisi, 8192)
            for t in (gt0, gt1, at0, at1):
                self.assertTrue(t.basarili, '\n'.join(mesajlar))
            geri = b''.join(alinan[i] for i in sorted(alinan))
            self.assertEqual(geri, zip_verisi)


# ==============================================================================
# 5. GECIKME VE PAKET KAYBI DAYANIKLILIK TESTLERI
# ==============================================================================

class SahtePortGecikmeli(SahtePort):
    """Alici taraf READY'yi gec gonderir (gonderici biraz beklemek zorunda)."""

    def __init__(self, *args, gecikme: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self._gecikme  = gecikme
        self._ilk_yaz  = True

    def write(self, data: bytes) -> int:
        if self._ilk_yaz and self._gecikme > 0:
            time.sleep(self._gecikme)
            self._ilk_yaz = False
        return super().write(data)


class SahteAlThreadGecikmeli(SahteAlThread):
    """Ilk READY paketini atmadan once bekler."""
    def __init__(self, *args, gecikme: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self._gecikme = gecikme

    def run(self):
        if self._gecikme > 0:
            time.sleep(self._gecikme)
        super().run()


class DayaniklilikTestleri(unittest.TestCase):

    def _transfer_yap(self, gecikme_sn: float, chunk_boyutu: int = 256):
        """
        Alici thread'leri `gecikme_sn` saniye gec baslar.
        Gonderici bu sureyi READY bekleme dongusunde gecirmelidir.
        """
        SIFRE = 'test'
        with tempfile.TemporaryDirectory() as kaynak:
            f = os.path.join(kaynak, 'test.bin')
            open(f, 'wb').write(os.urandom(20 * 1024))
            zip_verisi = zip_olustur([f], SIFRE)

        n      = len(zip_verisi)
        tum    = [(i, zip_verisi[o:o + chunk_boyutu])
                  for i, o in enumerate(range(0, n, chunk_boyutu))]
        toplam = len(tum)
        c0     = [(s, d) for s, d in tum if s % 2 == 0]
        c1     = [(s, d) for s, d in tum if s % 2 == 1]

        g0, a0 = port_cifti_olustur(timeout=2.0)
        g1, a1 = port_cifti_olustur(timeout=2.0)

        alinan: dict = {}
        kilit = threading.Lock()

        def chunk_topla(pi, seq, veri):
            with kilit:
                alinan[seq] = veri

        gt0 = SahteGonderThread(0, '', 0, c0, toplam, n, sahte_ser=g0)
        gt1 = SahteGonderThread(1, '', 0, c1, toplam, n, sahte_ser=g1)
        at0 = SahteAlThreadGecikmeli(0, '', 0, sahte_ser=a0, gecikme=gecikme_sn)
        at1 = SahteAlThreadGecikmeli(1, '', 0, sahte_ser=a1, gecikme=gecikme_sn)

        at0.sinyal_chunk.connect(chunk_topla, Qt.DirectConnection)
        at1.sinyal_chunk.connect(chunk_topla, Qt.DirectConnection)

        mesajlar = []
        for t in (gt0, gt1, at0, at1):
            t.sinyal_log.connect(lambda m: mesajlar.append(m), Qt.DirectConnection)

        # Gonderici once baslasin (gercek senaryoda Al/Gonder sirasiz baslanir)
        gt0.start(); gt1.start()
        time.sleep(0.1)
        at0.start(); at1.start()

        gt0.wait(90_000); gt1.wait(90_000)
        at0.wait(90_000); at1.wait(90_000)

        return gt0, gt1, at0, at1, alinan, mesajlar, zip_verisi

    def test_gonderici_once_basliyor(self):
        """Gonderici 2s once baslar, alici sonra READY gonderir."""
        gt0, gt1, at0, at1, alinan, mesajlar, zip_verisi = \
            self._transfer_yap(gecikme_sn=2.0)

        for t, isim in [(gt0,'gt0'),(gt1,'gt1'),(at0,'at0'),(at1,'at1')]:
            self.assertTrue(t.basarili,
                f"{isim} basarisiz — log:\n" + '\n'.join(mesajlar))

        geri = b''.join(alinan[i] for i in sorted(alinan))
        self.assertEqual(geri, zip_verisi, "ZIP verisi bozuldu!")
        print(f"\n  [OK] Gonderici 2s once basliyor — {len(alinan)} chunk aktarildi.")

    def test_alici_once_basliyor(self):
        """Alici 2s once baslar ve periyodik READY gonderir, gonderici sonra baslar."""
        SIFRE = 'test'
        with tempfile.TemporaryDirectory() as kaynak:
            f = os.path.join(kaynak, 'test.bin')
            open(f, 'wb').write(os.urandom(20 * 1024))
            zip_verisi = zip_olustur([f], SIFRE)

        n      = len(zip_verisi)
        chunk_boyutu = 256
        tum    = [(i, zip_verisi[o:o + chunk_boyutu])
                  for i, o in enumerate(range(0, n, chunk_boyutu))]
        toplam = len(tum)
        c0     = [(s, d) for s, d in tum if s % 2 == 0]
        c1     = [(s, d) for s, d in tum if s % 2 == 1]

        g0, a0 = port_cifti_olustur(timeout=2.0)
        g1, a1 = port_cifti_olustur(timeout=2.0)

        alinan: dict = {}
        kilit = threading.Lock()
        def chunk_topla(pi, seq, veri):
            with kilit:
                alinan[seq] = veri

        gt0 = SahteGonderThread(0, '', 0, c0, toplam, n, sahte_ser=g0)
        gt1 = SahteGonderThread(1, '', 0, c1, toplam, n, sahte_ser=g1)
        at0 = SahteAlThread(0, '', 0, sahte_ser=a0)
        at1 = SahteAlThread(1, '', 0, sahte_ser=a1)

        at0.sinyal_chunk.connect(chunk_topla, Qt.DirectConnection)
        at1.sinyal_chunk.connect(chunk_topla, Qt.DirectConnection)

        mesajlar = []
        for t in (gt0, gt1, at0, at1):
            t.sinyal_log.connect(lambda m: mesajlar.append(m), Qt.DirectConnection)

        # Alici 2s once basliyor
        at0.start(); at1.start()
        time.sleep(2.0)
        gt0.start(); gt1.start()

        gt0.wait(90_000); gt1.wait(90_000)
        at0.wait(90_000); at1.wait(90_000)

        for t, isim in [(gt0,'gt0'),(gt1,'gt1'),(at0,'at0'),(at1,'at1')]:
            self.assertTrue(t.basarili,
                f"{isim} basarisiz — log:\n" + '\n'.join(mesajlar))

        geri = b''.join(alinan[i] for i in sorted(alinan))
        self.assertEqual(geri, zip_verisi)
        print(f"\n  [OK] Alici 2s once basliyor — {len(alinan)} chunk aktarildi.")


# ==============================================================================
# CALISTIR
# ==============================================================================

if __name__ == '__main__':
    unittest.main(verbosity=2)
