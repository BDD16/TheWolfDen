#!/usr/bin/env python3
"""
payload_extractor.py

Defensive and forensic helper for scanning JPEG / Adobe DNG (TIFF+JPEG) files for
anomalous or appended payloads. DOES NOT attempt to exploit anything.

Run in a sandbox/VM. Do NOT execute extracted payloads.

Outputs:
 - JSON summary printed to stdout
 - Extracted APPn chunks and trailing data saved under <out_dir>/<filename>/
"""

import os
import sys
import struct
import hashlib
import json

JPEG_MARKER_PREFIX = b'\xff'
SOI = b'\xff\xd8'
EOI = b'\xff\xd9'

def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()

def read_u16_be(b, off):
    return struct.unpack_from('>H', b, off)[0]

def find_jpeg_markers(data):
    """
    Yield tuples (offset, marker_byte, length, payload_bytes)
    For markers that carry a 2-byte length (APPn, COM, etc), length includes the two length bytes.
    For SOS (start of scan), the payload continues until the next 0xff marker followed by 0xd9 (EOI),
    but here we yield the marker position; caller can handle compressed scan data detection.
    """
    i = 0
    n = len(data)
    while i < n - 1:
        if data[i] == 0xff:
            # skip padding 0xff bytes
            j = i + 1
            while j < n and data[j] == 0xff:
                j += 1
            if j >= n:
                break
            marker = data[j]
            marker_bytes = bytes([marker])
            marker_offset = i
            # standalone markers without length: SOI (D8), EOI (D9), RSTn (D0-D7)
            if marker in (0xd8, 0xd9) or (0xd0 <= marker <= 0xd7):
                yield (marker_offset, marker, 0, b'')
                i = j + 1
                continue
            # markers with length field
            if j + 2 <= n - 1:
                length = read_u16_be(data, j+1)
                payload_start = j+3
                payload_end = payload_start + (length - 2)
                if payload_end > n:
                    # truncated length: yield partial
                    payload = data[payload_start:n]
                else:
                    payload = data[payload_start:payload_end]
                yield (marker_offset, marker, length, payload)
                i = payload_end
                continue
            else:
                break
        else:
            i += 1

def extract_trailing_after_eoi(data):
    idx = data.find(EOI)
    if idx == -1:
        return None
    eoi_end = idx + 2
    if eoi_end >= len(data):
        return None
    trailing = data[eoi_end:]
    return eoi_end, trailing

def inspect_file(path, out_dir='extracted_artifacts'):
    basename = os.path.basename(path)
    with open(path, 'rb') as f:
        data = f.read()

    summary = {
        'file': basename,
        'size': len(data),
        'sha256': sha256_hex(data),
        'is_jpeg_like': False,
        'markers': [],
        'app_chunks': [],
        'trailing_after_eoi': False,
        'trailing_size': 0,
        'heuristics': []
    }

    # Quick check: is there a TIFF header (DNG often uses TIFF headers 'II' or 'MM')
    if data.startswith(b'II') or data.startswith(b'MM'):
        summary['tiff_like'] = True
        # Try to parse TIFF header: byte order + magic + first IFD offset
        try:
            byteorder = data[0:2]
            endian = '<' if byteorder == b'II' else '>'
            magic = struct.unpack_from(endian+'H', data, 2)[0]
            ifd0 = struct.unpack_from(endian+'I', data, 4)[0]
            summary['tiff_magic'] = int(magic)
            summary['tiff_ifd0_offset'] = int(ifd0)
            summary['heuristics'].append('tiff_header_present')
        except Exception as e:
            summary['tiff_parse_error'] = str(e)
    else:
        summary['tiff_like'] = False

    # Detect SOI
    if data.find(SOI) != -1:
        summary['is_jpeg_like'] = True

    # Walk JPEG markers
    markers = []
    for off, marker, length, payload in find_jpeg_markers(data):
        markers.append({
            'offset': off,
            'marker': hex(marker),
            'length_field': length,
            'payload_sha256': sha256_hex(payload) if payload else None,
            'payload_len': len(payload)
        })
        # record APPn
        if 0xe0 <= marker <= 0xef:  # APP0..APP15
            summary['app_chunks'].append({
                'offset': off,
                'marker': hex(marker),
                'length_field': length,
                'payload_len': len(payload),
                'payload_sha256': sha256_hex(payload) if payload else None
            })
    summary['markers'] = markers

    # Trailing data after EOI
    trailing = extract_trailing_after_eoi(data)
    if trailing:
        eoi_end, trailing_bytes = trailing
        summary['trailing_after_eoi'] = True
        summary['trailing_size'] = len(trailing_bytes)
        summary['heuristics'].append('trailing_data_after_eoi')
    else:
        summary['trailing_after_eoi'] = False

    # Heuristics: large APPn chunks, mismatches, anomalous trailing size
    for app in summary['app_chunks']:
        if app['payload_len'] > 1024 * 50:  # arbitrary threshold (50 KB)
            summary['heuristics'].append('large_app_chunk_{} at {}'.format(app['marker'], app['offset']))

    if summary['trailing_after_eoi'] and summary['trailing_size'] > 16:
        summary['heuristics'].append('nonempty_trailing_after_eoi')

    # Save extracted artifacts
    base_out = os.path.join(out_dir, basename)
    os.makedirs(base_out, exist_ok=True)
    # Save full file hash/summary
    summary_path = os.path.join(base_out, 'summary.json')
    with open(summary_path, 'w') as jf:
        json.dump(summary, jf, indent=2)

    # Save APP chunks as separate files
    for idx, app in enumerate(summary['app_chunks']):
        # find actual payload bytes again via offsets
        off = app['offset']
        # The payload starts after the 0xff marker and 2 byte length.
        # Re-parse to extract bytes reliably:
        # find marker position and marker byte
        if data[off:off+2][0] != 0xff:
            continue
        marker_byte = data[off+1]
        length_field = read_u16_be(data, off+2)
        payload_start = off + 4
        payload_end = payload_start + (length_field - 2)
        payload_bytes = data[payload_start:payload_end] if payload_end <= len(data) else data[payload_start:]
        out_name = os.path.join(base_out, f'app_chunk_{idx}_{hex(marker_byte)}.bin')
        with open(out_name, 'wb') as of:
            of.write(payload_bytes)

    # Save trailing bytes if present
    if summary['trailing_after_eoi']:
        eoi_pos = data.find(EOI)
        trailing_bytes = data[eoi_pos+2:]
        out_trail = os.path.join(base_out, 'trailing_after_eoi.bin')
        with open(out_trail, 'wb') as tf:
            tf.write(trailing_bytes)

    return summary, base_out

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} <image-file> [out_dir]".format(sys.argv[0]))
        sys.exit(2)
    path = sys.argv[1]
    od = sys.argv[2] if len(sys.argv) >= 3 else 'extracted_artifacts'
    s, out = inspect_file(path, od)
    print(json.dumps(s, indent=2))
    print("Extracted artifacts and summary written to:", out)
