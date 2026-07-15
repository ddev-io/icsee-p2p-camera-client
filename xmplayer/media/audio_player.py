from __future__ import annotations

import ctypes
import queue
import threading
import time
from ctypes import wintypes

from . import xstream_decoder as xd


WAVE_FORMAT_PCM = 1
WAVE_MAPPER = 0xFFFFFFFF
CALLBACK_NULL = 0
MMSYSERR_NOERROR = 0
WHDR_DONE = 0x00000001


class WAVEFORMATEX(ctypes.Structure):
    _fields_ = [
        ('wFormatTag', wintypes.WORD),
        ('nChannels', wintypes.WORD),
        ('nSamplesPerSec', wintypes.DWORD),
        ('nAvgBytesPerSec', wintypes.DWORD),
        ('nBlockAlign', wintypes.WORD),
        ('wBitsPerSample', wintypes.WORD),
        ('cbSize', wintypes.WORD),
    ]


class WAVEHDR(ctypes.Structure):
    _fields_ = [
        ('lpData', ctypes.c_void_p),
        ('dwBufferLength', wintypes.DWORD),
        ('dwBytesRecorded', wintypes.DWORD),
        ('dwUser', ctypes.c_size_t),
        ('dwFlags', wintypes.DWORD),
        ('dwLoops', wintypes.DWORD),
        ('lpNext', ctypes.c_void_p),
        ('reserved', ctypes.c_size_t),
    ]


class _WaveOutDevice:
    def __init__(self, *, sample_rate: int, channels: int = 1, bits_per_sample: int = 16, max_buffers: int = 32) -> None:
        self.sample_rate = int(sample_rate)
        self.channels = int(channels)
        self.bits_per_sample = int(bits_per_sample)
        self.max_buffers = max(int(max_buffers), 4)
        self._winmm = ctypes.windll.winmm
        self._handle = ctypes.c_void_p()
        self._pending: list[tuple[WAVEHDR, ctypes.Array[ctypes.c_char]]] = []
        self._lock = threading.Lock()
        self._opened = False
        self._configure_functions()

    def _configure_functions(self) -> None:
        self._winmm.waveOutOpen.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.UINT,
            ctypes.POINTER(WAVEFORMATEX),
            ctypes.c_size_t,
            ctypes.c_size_t,
            wintypes.DWORD,
        ]
        self._winmm.waveOutOpen.restype = wintypes.UINT
        self._winmm.waveOutPrepareHeader.argtypes = [ctypes.c_void_p, ctypes.POINTER(WAVEHDR), wintypes.UINT]
        self._winmm.waveOutPrepareHeader.restype = wintypes.UINT
        self._winmm.waveOutWrite.argtypes = [ctypes.c_void_p, ctypes.POINTER(WAVEHDR), wintypes.UINT]
        self._winmm.waveOutWrite.restype = wintypes.UINT
        self._winmm.waveOutUnprepareHeader.argtypes = [ctypes.c_void_p, ctypes.POINTER(WAVEHDR), wintypes.UINT]
        self._winmm.waveOutUnprepareHeader.restype = wintypes.UINT
        self._winmm.waveOutReset.argtypes = [ctypes.c_void_p]
        self._winmm.waveOutReset.restype = wintypes.UINT
        self._winmm.waveOutClose.argtypes = [ctypes.c_void_p]
        self._winmm.waveOutClose.restype = wintypes.UINT

    def open(self) -> bool:
        block_align = self.channels * self.bits_per_sample // 8
        fmt = WAVEFORMATEX(
            wFormatTag=WAVE_FORMAT_PCM,
            nChannels=self.channels,
            nSamplesPerSec=self.sample_rate,
            nAvgBytesPerSec=self.sample_rate * block_align,
            nBlockAlign=block_align,
            wBitsPerSample=self.bits_per_sample,
            cbSize=0,
        )
        result = self._winmm.waveOutOpen(
            ctypes.byref(self._handle),
            WAVE_MAPPER,
            ctypes.byref(fmt),
            0,
            0,
            CALLBACK_NULL,
        )
        self._opened = result == MMSYSERR_NOERROR and bool(self._handle.value)
        return self._opened

    def write_pcm16(self, pcm16: bytes, stop_event: threading.Event) -> bool:
        if not self._opened or not pcm16:
            return False
        while not stop_event.is_set():
            self.cleanup_done()
            with self._lock:
                if len(self._pending) < self.max_buffers:
                    break
            time.sleep(0.005)
        if stop_event.is_set():
            return False

        data = ctypes.create_string_buffer(pcm16)
        header = WAVEHDR()
        header.lpData = ctypes.cast(data, ctypes.c_void_p)
        header.dwBufferLength = len(pcm16)
        header.dwFlags = 0
        header_size = ctypes.sizeof(WAVEHDR)
        with self._lock:
            if self._winmm.waveOutPrepareHeader(self._handle, ctypes.byref(header), header_size) != MMSYSERR_NOERROR:
                return False
            if self._winmm.waveOutWrite(self._handle, ctypes.byref(header), header_size) != MMSYSERR_NOERROR:
                self._winmm.waveOutUnprepareHeader(self._handle, ctypes.byref(header), header_size)
                return False
            self._pending.append((header, data))
        return True

    def cleanup_done(self) -> None:
        if not self._opened:
            return
        header_size = ctypes.sizeof(WAVEHDR)
        with self._lock:
            kept: list[tuple[WAVEHDR, ctypes.Array[ctypes.c_char]]] = []
            for header, data in self._pending:
                if header.dwFlags & WHDR_DONE:
                    self._winmm.waveOutUnprepareHeader(self._handle, ctypes.byref(header), header_size)
                else:
                    kept.append((header, data))
            self._pending = kept

    def close(self) -> None:
        if not self._opened:
            return
        header_size = ctypes.sizeof(WAVEHDR)
        with self._lock:
            try:
                self._winmm.waveOutReset(self._handle)
            except Exception:
                pass
            for header, _data in self._pending:
                try:
                    self._winmm.waveOutUnprepareHeader(self._handle, ctypes.byref(header), header_size)
                except Exception:
                    pass
            self._pending.clear()
            try:
                self._winmm.waveOutClose(self._handle)
            except Exception:
                pass
            self._opened = False


class G711AudioPlayer:
    def __init__(
        self,
        *,
        codec: str = 'alaw',
        sample_rate: int = 8000,
        chunk_ms: int = 80,
        prebuffer_ms: int = 200,
        max_queue: int = 160,
    ) -> None:
        self.codec = codec
        self.sample_rate = max(int(sample_rate), 1)
        self.chunk_bytes = max(int(self.sample_rate * max(int(chunk_ms), 40) / 1000), 320)
        self.prebuffer_bytes = max(int(self.sample_rate * max(int(prebuffer_ms), 0) / 1000), self.chunk_bytes)
        self._queue: queue.Queue[bytes | None] = queue.Queue(maxsize=max(int(max_queue), 4))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._device: _WaveOutDevice | None = None

    def start(self) -> bool:
        if self._thread is not None:
            return True
        try:
            device = _WaveOutDevice(sample_rate=self.sample_rate)
        except Exception:
            return False
        if not device.open():
            return False
        self._device = device
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='xmplayer-audio-player')
        self._thread.start()
        return True

    def write_g711(self, payload: bytes) -> bool:
        if not payload or self._thread is None or self._stop_event.is_set():
            return False
        try:
            self._queue.put_nowait(bytes(payload))
            return True
        except queue.Full:
            return False

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=0.7)
        device = self._device
        self._device = None
        if device is not None:
            device.close()

    def _run(self) -> None:
        device = self._device
        if device is None:
            return
        buffer = bytearray()
        prebuffering = True
        try:
            while not self._stop_event.is_set():
                try:
                    item = self._queue.get(timeout=0.04)
                except queue.Empty:
                    item = b''
                if item is None:
                    break
                if item:
                    buffer.extend(item)
                elif not buffer:
                    device.cleanup_done()
                    continue

                if prebuffering and len(buffer) < self.prebuffer_bytes and item:
                    continue
                prebuffering = False

                while len(buffer) >= self.chunk_bytes and not self._stop_event.is_set():
                    g711_chunk = bytes(buffer[:self.chunk_bytes])
                    del buffer[:self.chunk_bytes]
                    pcm16 = xd.decode_g711_to_pcm16([g711_chunk], self.codec)
                    device.write_pcm16(pcm16, self._stop_event)
                    device.cleanup_done()

                if not item and buffer and not self._stop_event.is_set():
                    pcm16 = xd.decode_g711_to_pcm16([bytes(buffer)], self.codec)
                    buffer.clear()
                    device.write_pcm16(pcm16, self._stop_event)
                    device.cleanup_done()
        finally:
            device.close()
