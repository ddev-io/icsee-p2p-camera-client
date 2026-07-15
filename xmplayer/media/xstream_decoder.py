import argparse
import hashlib
import json
import re
import wave
from collections import Counter, defaultdict
from pathlib import Path


MAGIC_FF01 = b"\xff\x01"
FF01_HEADER_LEN = 20


def le16(b):
    return int.from_bytes(b, "little")


def le32(b):
    return int.from_bytes(b, "little")


def reassemble(segments):
    segments = sorted(segments, key=lambda x: x[0])
    out = bytearray()
    next_seq = None
    for seq, data in segments:
        if not data:
            continue
        if next_seq is None:
            next_seq = seq
        if seq < next_seq:
            overlap = next_seq - seq
            if overlap >= len(data):
                continue
            data = data[overlap:]
            seq = next_seq
        if seq > next_seq:
            gap = seq - next_seq
            out.extend(b"\x00" * gap)
            next_seq = seq
        out.extend(data)
        next_seq += len(data)
    return bytes(out)


def parse_ff01_frames(stream: bytes):
    frames = []
    i = 0
    n = len(stream)
    while i + FF01_HEADER_LEN <= n:
        if stream[i] == 0xFF and stream[i + 1] == 0x01:
            ver = stream[i + 2]
            flags = stream[i + 3]
            session_id = le32(stream[i + 4:i + 8])
            seq = le32(stream[i + 8:i + 12])
            unk = le16(stream[i + 12:i + 14])
            cmd = le16(stream[i + 14:i + 16])
            length = le32(stream[i + 16:i + 20])
            payload_start = i + FF01_HEADER_LEN
            payload_end = payload_start + length
            if length >= 0 and payload_end <= n:
                payload = stream[payload_start:payload_end]
                frames.append({
                    "offset": i,
                    "ver": ver,
                    "flags": flags,
                    "session_id": session_id,
                    "seq": seq,
                    "unk": unk,
                    "cmd": cmd,
                    "length": length,
                    "payload": payload,
                })
                i = payload_end
                continue
        i += 1
    return frames


def extract_data_payload(stream: bytes):
    frames = parse_ff01_frames(stream)
    cmd_counts = Counter([f["cmd"] for f in frames])
    data_payload = bytearray()
    for fr in frames:
        if fr["cmd"] == 0x0584:
            data_payload.extend(fr["payload"])
    return frames, cmd_counts, bytes(data_payload)


def head_size_for_type(t, b):
    if t in (0xEA, 0xEC, 0xED, 0xEE):
        return b[4] + 5
    if t == 0xFC:
        return 8
    if t in (0xF9, 0xFA, 0xFD):
        return 8
    return 0x10


def payload_len_for_type(t, b):
    if t == 0xEA:
        return int.from_bytes(b[0x12:0x14], "little")
    if t == 0xEC:
        return int.from_bytes(b[0x14:0x18], "little")
    if t == 0xED:
        return int.from_bytes(b[0x0C:0x10], "little")
    if t == 0xEE:
        return int.from_bytes(b[0x10:0x14], "little")
    if t in (0xF9, 0xFA):
        return int.from_bytes(b[0x06:0x08], "little")
    if t == 0xFC:
        return 8 + int.from_bytes(b[0x0C:0x10], "little")
    if t == 0xFD:
        return (b[4] | (b[5] << 8) | (b[6] << 16))
    return (b[0x0C] | (b[0x0D] << 8) | (b[0x0E] << 16))


def decrypt_offset_for_type(t, b):
    # CSTDStream::ParseHead + CStream::GetHeadSize determine where OnVideoDecrypt
    # begins. This is not always the same as the transport framing header size.
    if t in (0xFC, 0xFE):
        # Inner private-media subtype-0 frames decrypt after:
        # 8-byte xstream header + 8-byte FC inner header.
        return 0x10
    if t in (0xEC, 0xEE):
        mode = (b[8] >> 2) & 0x0F
        return 0x14 if mode == 0 else 0x18
    return head_size_for_type(t, b)


def parse_xstream_frames(data: bytes):
    frames = []
    i = 0
    n = len(data)
    while i + 4 <= n:
        idx = data.find(b"\x00\x00\x01", i)
        if idx < 0 or idx + 4 > n:
            break
        t = data[idx + 3]
        if idx + 5 > n:
            break
        head = head_size_for_type(t, data[idx:])
        if idx + head > n:
            break
        try:
            plen = payload_len_for_type(t, data[idx:])
        except Exception:
            i = idx + 1
            continue
        total = head + plen
        if plen < 0 or total <= 0:
            i = idx + 1
            continue
        if idx + total > n:
            break
        frames.append((idx, t, head, plen, total))
        i = idx + total
    return frames


def consume_xstream_frames(data: bytes):
    frames = []
    i = 0
    n = len(data)
    while i + 4 <= n:
        idx = data.find(b"\x00\x00\x01", i)
        if idx < 0 or idx + 4 > n:
            break
        t = data[idx + 3]
        if idx + 5 > n:
            break
        head = head_size_for_type(t, data[idx:])
        if idx + head > n:
            break
        try:
            plen = payload_len_for_type(t, data[idx:])
        except Exception:
            i = idx + 1
            continue
        total = head + plen
        if plen < 0 or total <= 0:
            i = idx + 1
            continue
        if idx + total > n:
            break
        frames.append((data[idx:idx + total], t, head, plen, total))
        i = idx + total
    return frames, data[i:]


def build_key(random_str: str):
    if random_str is None:
        return None
    rs = random_str.encode("utf-8", errors="ignore")
    if len(rs) < 0x10:
        return bytes(0x80)
    fill = rs[:1] or b"\x00"
    padded = bytearray(fill * 0x24)
    padded[: min(len(rs), 0x24)] = rs[:0x24]
    key = bytearray(0x80)
    for i in range(8):
        chunk = bytes(padded[i * 4:i * 4 + 8])
        key[i * 16:i * 16 + 16] = hashlib.md5(chunk).digest()
    return bytes(key)


def on_video_decrypt(key: bytes, frame: bytes, head_size: int):
    if key is None:
        return frame
    n = len(frame)
    out = bytearray(frame)
    max_i = min(0x80, n - head_size)
    for i in range(max_i):
        out[head_size + i] ^= key[(key[i] + n) % 0x80]
        out[head_size + i] ^= (n % 0xFD)
    return bytes(out)


def scan_nal_types(payload: bytes):
    h264 = Counter()
    h265 = Counter()
    i = 0
    while True:
        idx = payload.find(b"\x00\x00\x00\x01", i)
        if idx < 0 or idx + 5 > len(payload):
            break
        nal = payload[idx + 4]
        h264[nal & 0x1F] += 1
        h265[(nal >> 1) & 0x3F] += 1
        i = idx + 4
    return h264, h265


def parse_hevc_annexb_unit(payload: bytes):
    if len(payload) < 6:
        return None
    if not payload.startswith(b"\x00\x00\x00\x01"):
        return None
    nal_header = payload[4:6]
    nal_type = (nal_header[0] >> 1) & 0x3F
    layer_id = ((nal_header[0] & 0x01) << 5) | (nal_header[1] >> 3)
    temporal_id_plus1 = nal_header[1] & 0x07
    return {
        "nal_header_hex": nal_header.hex(),
        "h265_nal_type": nal_type,
        "h265_layer_id": layer_id,
        "h265_temporal_id_plus1": temporal_id_plus1,
        "body_head_hex": payload[6:38].hex(),
        "payload_len": len(payload),
    }


def parse_fc_payload(payload: bytes):
    if len(payload) < 8:
        return None
    meta_u32_le = int.from_bytes(payload[0:4], "little")
    blob_len_le = int.from_bytes(payload[4:8], "little")
    blob = payload[8:]
    hevc = parse_hevc_annexb_unit(blob)
    return {
        "meta_u32_le": meta_u32_le,
        "meta_u32_hex": f"0x{meta_u32_le:08x}",
        "blob_len_le": blob_len_le,
        "actual_blob_len": len(blob),
        "blob_len_matches": blob_len_le == len(blob),
        "header_hex": payload[:8].hex(),
        "blob_head_hex": blob[:48].hex(),
        "blob_tail_hex": blob[-32:].hex() if blob else "",
        "blob_starts_annexb": blob.startswith(b"\x00\x00\x00\x01"),
        "blob_second_startcode_at": blob.find(b"\x00\x00\x00\x01", 4),
        "blob_h265_nal_type": hevc["h265_nal_type"] if hevc else None,
        "blob": blob,
    }


def summarize_audio_candidate(payloads):
    if not payloads:
        return None
    lengths = Counter(len(payload) for payload in payloads)
    merged = b"".join(payloads)
    byte_counts = Counter(merged)
    g711aish = [0x55, 0xD5, 0x54, 0x56, 0x57, 0xD4, 0xD6, 0xD7]
    ratio = (sum(byte_counts[value] for value in g711aish) / len(merged)) if merged else 0.0
    likely_codec = ""
    if lengths == Counter({320: len(payloads)}) and ratio > 0.50:
        likely_codec = "g711a_like"
    return {
        "frame_count": len(payloads),
        "payload_sizes": {str(length): count for length, count in lengths.most_common(8)},
        "byte_top": {f"0x{value:02x}": count for value, count in byte_counts.most_common(12)},
        "g711aish_ratio": round(ratio, 4),
        "likely_codec": likely_codec,
    }


def summarize_inner_d0_cycles(entries):
    if not entries:
        return {"count": 0, "codes": {}, "cycles": []}
    codes = Counter(entry["opcode_be"] for entry in entries)
    cycles = []
    current = []
    last_tail = None
    for entry in entries:
        tail = int(entry["tail"])
        if last_tail is not None and tail <= last_tail:
            cycles.append(current)
            current = []
        current.append(entry)
        last_tail = tail
    if current:
        cycles.append(current)
    cycle_rows = []
    for idx, cycle in enumerate(cycles, start=1):
        seq_slots = [item.get("seq_slot") for item in cycle if item.get("seq_slot") is not None]
        cycle_rows.append(
            {
                "cycle_index": idx,
                "frame_count": len(cycle),
                "tail_range": [int(cycle[0]["tail"]), int(cycle[-1]["tail"])],
                "seq_slot_range": [int(seq_slots[0]), int(seq_slots[-1])] if seq_slots else [],
                "payload_bytes": sum(int(item["payload_len"]) for item in cycle),
                "first_codes": [item["opcode_be"] for item in cycle[:6]],
                "last_codes": [item["opcode_be"] for item in cycle[-6:]],
            }
        )
    resets = [
        {"index": idx, "prev": entries[idx - 1]["tail"], "current": entries[idx]["tail"]}
        for idx in range(1, len(entries))
        if int(entries[idx]["tail"]) <= int(entries[idx - 1]["tail"])
    ]
    return {
        "count": len(entries),
        "codes": {key: value for key, value in codes.items()},
        "tail_resets": resets,
        "cycles": cycle_rows,
        "seq_slots_head": [item.get("seq_slot") for item in entries[:16]],
        "first_frames": entries[:12],
    }


def build_gop_rows(entries):
    rows = []
    current = None
    gop_id = -1
    for entry in entries:
        t = entry["frame_type"]
        if t == 0xF9:
            gop_id += 1
            current = {
                "gop_id": gop_id,
                "start_xstream_index": entry["xstream_index"],
                "boundary_count": 1,
                "fc_count": 0,
                "fc_blob_lens": [],
                "fd_count": 0,
                "fd_h265_nal_types": {},
                "fa_count": 0,
                "fa_payload_bytes": 0,
            }
            rows.append(current)
            continue
        if current is None:
            gop_id = 0
            current = {
                "gop_id": gop_id,
                "start_xstream_index": entry["xstream_index"],
                "boundary_count": 0,
                "fc_count": 0,
                "fc_blob_lens": [],
                "fd_count": 0,
                "fd_h265_nal_types": {},
                "fa_count": 0,
                "fa_payload_bytes": 0,
            }
            rows.append(current)
        if t == 0xFC:
            current["fc_count"] += 1
            if isinstance(entry.get("actual_blob_len"), int):
                current["fc_blob_lens"].append(entry["actual_blob_len"])
        elif t == 0xFD:
            current["fd_count"] += 1
            nal_type = entry.get("h265_nal_type")
            if isinstance(nal_type, int):
                key = str(nal_type)
                current["fd_h265_nal_types"][key] = int(current["fd_h265_nal_types"].get(key, 0)) + 1
        elif t == 0xFA:
            current["fa_count"] += 1
            current["fa_payload_bytes"] += int(entry.get("payload_len") or 0)
    for row in rows:
        if row["fa_payload_bytes"]:
            row["fa_duration_sec_8k"] = round(row["fa_payload_bytes"] / 8000.0, 3)
    return rows


def _decode_alaw_byte(value: int) -> int:
    value ^= 0x55
    sign = value & 0x80
    exponent = (value & 0x70) >> 4
    mantissa = value & 0x0F
    sample = mantissa << 4
    if exponent == 0:
        sample += 8
    else:
        sample += 0x108
        sample <<= exponent - 1
    return -sample if sign else sample


def _decode_mulaw_byte(value: int) -> int:
    value = (~value) & 0xFF
    sign = value & 0x80
    exponent = (value >> 4) & 0x07
    mantissa = value & 0x0F
    sample = ((mantissa << 3) + 0x84) << exponent
    sample -= 0x84
    return -sample if sign else sample


def decode_g711_to_pcm16(payloads, codec: str):
    out = bytearray()
    decoder = _decode_alaw_byte if codec == "alaw" else _decode_mulaw_byte
    for payload in payloads:
        for value in payload:
            out.extend(int(decoder(value)).to_bytes(2, "little", signed=True))
    return bytes(out)


def write_pcm16_wav(path: Path, pcm16: bytes, sample_rate: int = 8000, channels: int = 1):
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(pcm16)


def load_pcap_streams(pcap_path: Path, port: int):
    try:
        from scapy.all import PcapNgReader, TCP, Raw, IP, IPv6
    except Exception as exc:
        raise RuntimeError(f"scapy is required for pcap parsing: {exc}") from exc

    flows = defaultdict(list)
    with PcapNgReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            if TCP in pkt and Raw in pkt:
                tcp = pkt[TCP]
                data = bytes(pkt[Raw])
                if not data:
                    continue
                if tcp.sport != port and tcp.dport != port:
                    continue
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif IPv6 in pkt:
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                else:
                    continue
                key = (src, tcp.sport, dst, tcp.dport)
                flows[key].append((tcp.seq, data))

    streams = []
    for key, segs in flows.items():
        stream = reassemble(segs)
        frames, cmd_counts, data_payload = extract_data_payload(stream)
        streams.append({
            "key": key,
            "segments": len(segs),
            "stream_len": len(stream),
            "ff01_frames": len(frames),
            "ff01_cmd_counts": {int(k): int(v) for k, v in cmd_counts.items()},
            "data_payload_len": len(data_payload),
            "data_payload": data_payload,
            "raw_stream": stream,
        })
    return streams


def extract_random_str_from_hook_log(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'"random_str":"([^"]+)"', text)
    if match:
        return match.group(1)
    return None


def extract_media_random_str_from_json(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    candidates = [
        data.get("vekey1"),
        ((data.get("claim") or {}).get("built_login") or {}).get("vekey1_raw"),
        ((data.get("tcp_probe") or {}).get("vekey1")),
        ((((data.get("tcp_probe") or {}).get("claim") or {}).get("built_login") or {}).get("vekey1_raw")),
        (((data.get("tcp_encrypted_probe") or {}).get("vekey1")) if isinstance(data.get("tcp_encrypted_probe"), dict) else None),
        (((((data.get("tcp_encrypted_probe") or {}).get("claim") or {}).get("built_login") or {}).get("vekey1_raw")) if isinstance(data.get("tcp_encrypted_probe"), dict) else None),
        data.get("media_random_str"),
        ((data.get("claim") or {}).get("built_login") or {}).get("media_random_str_raw"),
        ((data.get("tcp_probe") or {}).get("media_random_str")),
        ((((data.get("tcp_probe") or {}).get("claim") or {}).get("built_login") or {}).get("media_random_str_raw")),
        (((data.get("tcp_encrypted_probe") or {}).get("media_random_str")) if isinstance(data.get("tcp_encrypted_probe"), dict) else None),
        (((((data.get("tcp_encrypted_probe") or {}).get("claim") or {}).get("built_login") or {}).get("media_random_str_raw")) if isinstance(data.get("tcp_encrypted_probe"), dict) else None),
        (((((data.get("plain_handoff_runs") or [{}])[0].get("probe") or {}).get("media_random_str")) if isinstance(data.get("plain_handoff_runs"), list) and data.get("plain_handoff_runs") else None)),
    ]
    for candidate in candidates:
        if isinstance(candidate, str) and len(candidate) == 64:
            return candidate
    return None


def _walk_values(obj):
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _walk_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_values(item)


def extract_media_random_str_from_first6611_json(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    for item in _walk_values(data):
        if not isinstance(item, dict):
            continue
        candidate = None
        if isinstance(item.get("VEKEY1"), str):
            candidate = item.get("VEKEY1")
        else:
            monitor = item.get("OPMonitor")
            if isinstance(monitor, dict):
                params = monitor.get("Parameter")
                if isinstance(params, dict) and isinstance(params.get("VEKEY1"), str):
                    candidate = params.get("VEKEY1")
        if isinstance(candidate, str) and len(candidate) == 64:
            return candidate
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", help="pcapng to parse (optional)")
    ap.add_argument("--input", help="raw data payload bin (optional)")
    ap.add_argument("--port", type=int, default=6611)
    ap.add_argument("--flow", type=int, default=None, help="flow index to use (pcap only)")
    ap.add_argument("--random-str", default=None)
    ap.add_argument("--random-str-log", help="Frida hook log with GET_DECRYPT_KEY random_str")
    ap.add_argument("--random-str-json", help="Client run JSON with media_random_str")
    ap.add_argument("--first6611-json", help="Decoded first-6611 JSON containing VEKEY1")
    ap.add_argument("--decrypt", action="store_true")
    ap.add_argument("--out-video")
    ap.add_argument("--out-audio")
    ap.add_argument("--out-audio-wav")
    ap.add_argument("--audio-codec", choices=["alaw", "mulaw"], default="alaw")
    ap.add_argument("--audio-rate", type=int, default=8000)
    ap.add_argument("--out-fc-dir")
    ap.add_argument("--out-gop-dir")
    ap.add_argument("--out-json")
    args = ap.parse_args()

    if not args.pcap and not args.input:
        raise SystemExit("Provide --pcap or --input")

    data = None
    meta = {}
    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            raise SystemExit(f"pcap not found: {pcap_path}")
        streams = load_pcap_streams(pcap_path, args.port)
        if not streams:
            raise SystemExit("No matching TCP streams found")
        streams_sorted = sorted(streams, key=lambda s: s["data_payload_len"], reverse=True)
        if args.flow is not None:
            if args.flow < 0 or args.flow >= len(streams_sorted):
                raise SystemExit(f"flow index out of range: {args.flow}")
            chosen = streams_sorted[args.flow]
        else:
            chosen = streams_sorted[0]
        data = chosen["data_payload"] or chosen["raw_stream"]
        meta["pcap_flow"] = {
            "key": chosen["key"],
            "segments": chosen["segments"],
            "stream_len": chosen["stream_len"],
            "ff01_frames": chosen["ff01_frames"],
            "ff01_cmd_counts": chosen["ff01_cmd_counts"],
            "data_payload_len": chosen["data_payload_len"],
        }
        meta["pcap_flow_index"] = streams_sorted.index(chosen)
        meta["pcap_flows_total"] = len(streams_sorted)
    else:
        in_path = Path(args.input)
        if not in_path.exists():
            raise SystemExit(f"input not found: {in_path}")
        data = in_path.read_bytes()
        meta["input_path"] = str(in_path)
        meta["input_len"] = len(data)

    frames = parse_xstream_frames(data)
    if not frames:
        raise SystemExit("No XStream frames parsed")

    random_str = args.random_str
    if args.decrypt and not random_str and args.random_str_log:
        hook_path = Path(args.random_str_log)
        if hook_path.exists():
            random_str = extract_random_str_from_hook_log(hook_path)
            if random_str:
                meta["random_str_from_log"] = str(hook_path)
                meta["random_str_len"] = len(random_str)
    if args.decrypt and not random_str and args.random_str_json:
        json_path = Path(args.random_str_json)
        if json_path.exists():
            random_str = extract_media_random_str_from_json(json_path)
            if random_str:
                meta["random_str_from_json"] = str(json_path)
                meta["random_str_len"] = len(random_str)
    if args.decrypt and not random_str and args.first6611_json:
        first_json_path = Path(args.first6611_json)
        if first_json_path.exists():
            random_str = extract_media_random_str_from_first6611_json(first_json_path)
            if random_str:
                meta["random_str_from_first6611_json"] = str(first_json_path)
                meta["random_str_len"] = len(random_str)
    key = build_key(random_str) if args.decrypt else None
    if args.decrypt and random_str is None:
        print("WARN: --decrypt set but no random_str available; decryption skipped")

    video_types = {0xEC, 0xED, 0xEE, 0xFD, 0xFC, 0xFE}
    decrypt_types = {0xEC, 0xEE, 0xFC, 0xFE}
    audio_types = {0xEA, 0xFA}
    video = bytearray()
    audio = bytearray()
    type_counts = Counter([t for _, t, _, _, _ in frames])
    fa_payloads = []
    fd_hevc_entries = []
    fc_entries = []
    annexb_scan_payload = bytearray()
    xstream_entries = []

    for idx, (off, t, head, plen, total) in enumerate(frames):
        frame = data[off:off + total]
        if args.decrypt and key is not None and t in decrypt_types:
            frame = on_video_decrypt(key, frame, decrypt_offset_for_type(t, frame))
        payload = frame[head:head + plen]
        row = {
            "xstream_index": idx,
            "offset": off,
            "frame_type": t,
            "frame_type_hex": f"0x{t:02x}",
            "payload_len": len(payload),
        }
        if t in video_types:
            if t == 0xFD:
                hevc = parse_hevc_annexb_unit(payload)
                if hevc:
                    row.update(hevc)
                    fd_hevc_entries.append({"xstream_index": idx, **hevc})
                video.extend(payload)
                annexb_scan_payload.extend(payload)
            elif t == 0xFC:
                fc = parse_fc_payload(payload)
                if fc:
                    row.update({k: v for k, v in fc.items() if k != "blob"})
                    fc_entries.append({"xstream_index": idx, **fc})
                    video.extend(fc["blob"])
                    annexb_scan_payload.extend(fc["blob"])
                else:
                    video.extend(payload)
            else:
                video.extend(payload)
                annexb_scan_payload.extend(payload)
        elif t in audio_types:
            audio.extend(payload)
            if t == 0xFA:
                fa_payloads.append(payload)
        xstream_entries.append(row)

    h264, h265 = scan_nal_types(bytes(annexb_scan_payload))

    report = {
        "frames_total": len(frames),
        "frame_types": {f"0x{k:02x}": int(v) for k, v in type_counts.items()},
        "video_bytes": len(video),
        "audio_bytes": len(audio),
        "h264_nal_types": h264.most_common(12),
        "h265_nal_types": h265.most_common(12),
    }
    audio_candidate = summarize_audio_candidate(fa_payloads)
    if audio_candidate:
        report["audio_candidate"] = audio_candidate
    if fd_hevc_entries:
        report["fd_hevc_entries"] = fd_hevc_entries[:12]
        report["fd_h265_nal_types"] = {
            str(key): value
            for key, value in Counter(entry["h265_nal_type"] for entry in fd_hevc_entries).most_common(12)
        }
    if fc_entries:
        report["fc_entries"] = [
            {
                "xstream_index": entry["xstream_index"],
                "meta_u32_hex": entry["meta_u32_hex"],
                "blob_len_le": entry["blob_len_le"],
                "actual_blob_len": entry["actual_blob_len"],
                "blob_len_matches": entry["blob_len_matches"],
                "header_hex": entry["header_hex"],
                "blob_head_hex": entry["blob_head_hex"],
                "blob_tail_hex": entry["blob_tail_hex"],
                "blob_starts_annexb": entry["blob_starts_annexb"],
                "blob_second_startcode_at": entry["blob_second_startcode_at"],
                "blob_h265_nal_type": entry["blob_h265_nal_type"],
            }
            for entry in fc_entries
        ]
        report["fc_decrypt_summary"] = {
            "entries_total": len(fc_entries),
            "annexb_ready_count": sum(1 for entry in fc_entries if entry["blob_starts_annexb"]),
            "first_h265_nal_types": [
                entry["blob_h265_nal_type"]
                for entry in fc_entries
                if isinstance(entry["blob_h265_nal_type"], int)
            ],
        }
    gop_rows = build_gop_rows(xstream_entries)
    if gop_rows:
        report["gop_rows"] = gop_rows
    report.update(meta)

    if args.out_video:
        Path(args.out_video).write_bytes(bytes(video))
    if args.out_audio:
        Path(args.out_audio).write_bytes(bytes(audio))
    if args.out_audio_wav and fa_payloads:
        pcm16 = decode_g711_to_pcm16(fa_payloads, args.audio_codec)
        out_wav = Path(args.out_audio_wav)
        write_pcm16_wav(out_wav, pcm16, sample_rate=args.audio_rate)
        report["audio_wav"] = {
            "path": str(out_wav),
            "codec": args.audio_codec,
            "sample_rate": args.audio_rate,
            "pcm16_bytes": len(pcm16),
            "duration_sec": round(len(pcm16) / 2 / max(args.audio_rate, 1), 3),
        }
    if args.out_fc_dir and fc_entries:
        out_dir = Path(args.out_fc_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        fc_written = []
        for idx, entry in enumerate(fc_entries, start=1):
            blob_path = out_dir / f"fc_{idx:02d}_xstream{entry['xstream_index']:03d}_{entry['actual_blob_len']}.bin"
            blob_path.write_bytes(entry["blob"])
            fc_written.append(
                {
                    "index": idx,
                    "xstream_index": entry["xstream_index"],
                    "path": str(blob_path),
                    "blob_len": entry["actual_blob_len"],
                }
            )
        report["fc_blob_files"] = fc_written
    if args.out_gop_dir:
        out_dir = Path(args.out_gop_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        gop_dirs = []
        current_gop = -1
        gop_path = None
        fa_index = 0
        fd_index = 0
        fc_index = 0
        for idx, (off, t, head, plen, total) in enumerate(frames):
            frame = data[off:off + total]
            if args.decrypt and key is not None and t in decrypt_types:
                frame = on_video_decrypt(key, frame, decrypt_offset_for_type(t, frame))
            payload = frame[head:head + plen]
            if t == 0xF9 or gop_path is None:
                current_gop += 1
                fa_index = 0
                fd_index = 0
                fc_index = 0
                gop_path = out_dir / f"gop_{current_gop:02d}"
                gop_path.mkdir(parents=True, exist_ok=True)
                gop_dirs.append({"gop_id": current_gop, "path": str(gop_path)})
            if t == 0xFC:
                fc = parse_fc_payload(payload)
                fc_index += 1
                if fc:
                    (gop_path / f"fc_{fc_index:02d}_header.bin").write_bytes(payload[:8])
                    (gop_path / f"fc_{fc_index:02d}_blob.bin").write_bytes(fc["blob"])
            elif t == 0xFD:
                hevc = parse_hevc_annexb_unit(payload)
                fd_index += 1
                nal_type = hevc.get("h265_nal_type") if hevc else None
                nal_part = f"nal{nal_type:02d}_" if isinstance(nal_type, int) else ""
                (gop_path / f"fd_{fd_index:02d}_{nal_part}payload.bin").write_bytes(payload)
            elif t == 0xFA:
                fa_index += 1
                (gop_path / f"fa_{fa_index:03d}.bin").write_bytes(payload)
        report["gop_dirs"] = gop_dirs
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
