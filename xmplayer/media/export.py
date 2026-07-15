from __future__ import annotations

import base64
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import xstream_decoder as xd


class ExportError(RuntimeError):
    pass


@dataclass(slots=True)
class ExportArtifacts:
    run_json_path: Path
    payload_bin_path: Path
    report_path: Path
    summary_path: Path
    video_path: Path
    audio_wav_path: Path | None
    report: dict[str, Any]
    summary: dict[str, Any]


def _find_second_probe(run_json: dict[str, Any]) -> dict[str, Any]:
    runs = run_json.get('plain_handoff_runs') or []
    for run in runs:
        probe = run.get('probe') or {}
        frames = probe.get('frames') or {}
        if frames.get('data_frames'):
            return run
    raise ExportError('no_plain_handoff_data_frames')


def _build_payload_bin(data_frames: list[dict[str, Any]]) -> bytes:
    blob = bytearray()
    for frame in data_frames:
        payload_b64 = frame.get('payload_b64')
        if not payload_b64:
            continue
        blob.extend(base64.b64decode(payload_b64))
    if not blob:
        raise ExportError('empty_payload_b64_stream')
    return bytes(blob)


def decode_payload_bin(payload_bin: bytes, random_str: str | None, *, audio_codec: str = 'alaw', audio_rate: int = 8000) -> tuple[dict[str, Any], bytes, bytes]:
    frames = xd.parse_xstream_frames(payload_bin)
    if not frames:
        raise ExportError('No XStream frames parsed')

    key = xd.build_key(random_str) if random_str else None
    video_types = {0xEC, 0xED, 0xEE, 0xFD, 0xFC, 0xFE}
    decrypt_types = {0xEC, 0xEE, 0xFC, 0xFE}
    audio_types = {0xEA, 0xFA}
    video = bytearray()
    audio = bytearray()
    type_counts = Counter([frame_type for _, frame_type, _, _, _ in frames])
    fa_payloads: list[bytes] = []
    fd_hevc_entries: list[dict[str, Any]] = []
    fc_entries: list[dict[str, Any]] = []
    annexb_scan_payload = bytearray()
    xstream_entries: list[dict[str, Any]] = []

    for idx, (off, frame_type, head, plen, total) in enumerate(frames):
        frame = payload_bin[off:off + total]
        if key is not None and frame_type in decrypt_types:
            frame = xd.on_video_decrypt(key, frame, xd.decrypt_offset_for_type(frame_type, frame))
        payload = frame[head:head + plen]
        row = {
            'xstream_index': idx,
            'offset': off,
            'frame_type': frame_type,
            'frame_type_hex': f'0x{frame_type:02x}',
            'payload_len': len(payload),
        }
        if frame_type in video_types:
            if frame_type == 0xFD:
                hevc = xd.parse_hevc_annexb_unit(payload)
                if hevc:
                    row.update(hevc)
                    fd_hevc_entries.append({'xstream_index': idx, **hevc})
                video.extend(payload)
                annexb_scan_payload.extend(payload)
            elif frame_type == 0xFC:
                fc = xd.parse_fc_payload(payload)
                if fc:
                    row.update({k: v for k, v in fc.items() if k != 'blob'})
                    fc_entries.append({'xstream_index': idx, **fc})
                    video.extend(fc['blob'])
                    annexb_scan_payload.extend(fc['blob'])
                else:
                    video.extend(payload)
            else:
                video.extend(payload)
                annexb_scan_payload.extend(payload)
        elif frame_type in audio_types:
            audio.extend(payload)
            if frame_type == 0xFA:
                fa_payloads.append(payload)
        xstream_entries.append(row)

    h264, h265 = xd.scan_nal_types(bytes(annexb_scan_payload))
    report: dict[str, Any] = {
        'frames_total': len(frames),
        'frame_types': {f'0x{k:02x}': int(v) for k, v in type_counts.items()},
        'video_bytes': len(video),
        'audio_bytes': len(audio),
        'h264_nal_types': h264.most_common(12),
        'h265_nal_types': h265.most_common(12),
    }
    audio_candidate = xd.summarize_audio_candidate(fa_payloads)
    if audio_candidate:
        report['audio_candidate'] = audio_candidate
    if fd_hevc_entries:
        report['fd_hevc_entries'] = fd_hevc_entries[:12]
        report['fd_h265_nal_types'] = {
            str(key): value
            for key, value in Counter(entry['h265_nal_type'] for entry in fd_hevc_entries).most_common(12)
        }
    if fc_entries:
        report['fc_entries'] = [
            {
                'xstream_index': entry['xstream_index'],
                'meta_u32_hex': entry['meta_u32_hex'],
                'blob_len_le': entry['blob_len_le'],
                'actual_blob_len': entry['actual_blob_len'],
                'blob_len_matches': entry['blob_len_matches'],
                'header_hex': entry['header_hex'],
                'blob_head_hex': entry['blob_head_hex'],
                'blob_tail_hex': entry['blob_tail_hex'],
                'blob_starts_annexb': entry['blob_starts_annexb'],
                'blob_second_startcode_at': entry['blob_second_startcode_at'],
                'blob_h265_nal_type': entry['blob_h265_nal_type'],
            }
            for entry in fc_entries
        ]
        report['fc_decrypt_summary'] = {
            'entries_total': len(fc_entries),
            'annexb_ready_count': sum(1 for entry in fc_entries if entry['blob_starts_annexb']),
            'first_h265_nal_types': [
                entry['blob_h265_nal_type']
                for entry in fc_entries
                if isinstance(entry['blob_h265_nal_type'], int)
            ],
        }
    gop_rows = xd.build_gop_rows(xstream_entries)
    if gop_rows:
        report['gop_rows'] = gop_rows
    if random_str:
        report['random_str_len'] = len(random_str)
    return report, bytes(video), bytes(audio)


def export_run_json(run_json_path: str | Path, *, audio_codec: str = 'alaw', audio_rate: int = 8000) -> ExportArtifacts:
    run_json_path = Path(run_json_path).resolve()
    run_json = json.loads(run_json_path.read_text(encoding='utf-8'))
    second_run = _find_second_probe(run_json)
    probe = second_run.get('probe') or {}
    frames = probe.get('frames') or {}
    data_frames = frames.get('data_frames') or []
    payload_bin = _build_payload_bin(data_frames)
    random_str = xd.extract_media_random_str_from_json(run_json_path)
    report, video_bytes, audio_bytes = decode_payload_bin(payload_bin, random_str, audio_codec=audio_codec, audio_rate=audio_rate)

    out_prefix = run_json_path.with_suffix('')
    payload_bin_path = out_prefix.with_suffix('.bin')
    video_path = out_prefix.with_suffix('.h265')
    wav_path = out_prefix.with_suffix('.wav')
    report_path = out_prefix.with_name(out_prefix.name + '_decode.json')
    summary_path = out_prefix.with_name(out_prefix.name + '_summary.json')

    payload_bin_path.write_bytes(payload_bin)
    video_path.write_bytes(video_bytes)
    audio_wav_path: Path | None = None
    if audio_bytes:
        pcm16 = xd.decode_g711_to_pcm16([audio_bytes], audio_codec)
        xd.write_pcm16_wav(wav_path, pcm16, sample_rate=audio_rate)
        audio_wav_path = wav_path
        report['audio_wav'] = {
            'path': str(wav_path),
            'codec': audio_codec,
            'sample_rate': audio_rate,
            'pcm16_bytes': len(pcm16),
            'duration_sec': round(len(pcm16) / 2 / max(audio_rate, 1), 3),
        }
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

    summary = {
        'run_json': str(run_json_path),
        'payload_bin_path': str(payload_bin_path),
        'video_path': str(video_path),
        'audio_wav_path': str(audio_wav_path) if audio_wav_path else '',
        'report_path': str(report_path),
        'second_probe_status': probe.get('status'),
        'second_data_frames': len(data_frames),
        'second_data_bytes': len(payload_bin),
        'frame_types': report.get('frame_types'),
        'fc_annexb_ready_count': ((report.get('fc_decrypt_summary') or {}).get('annexb_ready_count')),
        'audio_bytes': report.get('audio_bytes'),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    return ExportArtifacts(
        run_json_path=run_json_path,
        payload_bin_path=payload_bin_path,
        report_path=report_path,
        summary_path=summary_path,
        video_path=video_path,
        audio_wav_path=audio_wav_path,
        report=report,
        summary=summary,
    )
