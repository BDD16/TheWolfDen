#!/usr/bin/env python3
"""
carve_and_package_payloads.py

Verbose & robust version of the carving tool.

example usage: python3 carve_and_package_payloads_verbose.py IMG_0118.JPG --outdir carved_output --make-object-elf


example command to decompile: objdump -D -M intel -C payload_as_object.elf > disasm_all.txt


Behavior:
 - Reports file size, EOI offsets, and reasons when nothing is written.
 - Writes payload.bin (trailer after EOI) to the outdir and prints full paths.
 - If no EOI found, supports --force to write the whole file or --carve-from-offset N.
 - Optional --make-object-elf wraps payload into a non-executable ELF object for static analysis.

Usage examples:
  python3 carve_and_package_payloads_verbose.py IMG_0118.JPG --outdir carved_output --make-object-elf
  python3 carve_and_package_payloads_verbose.py file.jpg --force --outdir carved_output
  python3 carve_and_package_payloads_verbose.py file.jpg --carve-from-offset 51200 --outdir carved_output
"""
import argparse
import os
import sys
import hashlib
import struct

EOI = b'\xff\xd9'

def sha256_hex(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def find_eoi(data: bytes, use_last=False):
    if use_last:
        return data.rfind(EOI)
    return data.find(EOI)

def write_file(path: str, data: bytes):
    try:
        with open(path, 'wb') as f:
            f.write(data)
        return True, None
    except Exception as e:
        return False, str(e)

# (minimal, same as prior helper)
def make_nonexec_elf_object(payload_bytes: bytes) -> bytes:
    ELF_HDR_SIZE = 64
    SHDR_SIZE = 64
    shstrtab = b'\x00.payload_data\x00.shstrtab\x00'
    sh_offset = ELF_HDR_SIZE
    num_sh = 3
    section_data_off = sh_offset + (SHDR_SIZE * num_sh)
    payload_off = section_data_off
    payload_size = len(payload_bytes)
    shstrtab_off = payload_off + payload_size
    shstrtab_size = len(shstrtab)
    e_ident = b'\x7fELF' + bytes([
        2, 1, 1, 0, 0
    ]) + bytes(7)
    e_type = 1
    e_machine = 62
    e_version = 1
    e_entry = 0
    e_phoff = 0
    e_shoff = sh_offset
    e_flags = 0
    e_ehsize = ELF_HDR_SIZE
    e_phentsize = 0
    e_phnum = 0
    e_shentsize = SHDR_SIZE
    e_shnum = num_sh
    e_shstrndx = 2
    elf_hdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident,
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx
    )
    sh_null = struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    name_payload = shstrtab.find(b'.payload_data')
    name_shstr = shstrtab.find(b'.shstrtab')
    sh_payload = struct.pack(
        '<IIQQQQIIQQ',
        name_payload,
        1,
        0,
        0,
        payload_off,
        payload_size,
        0,
        0,
        1,
        0
    )
    sh_shstr = struct.pack(
        '<IIQQQQIIQQ',
        name_shstr,
        3,
        0,
        0,
        shstrtab_off,
        shstrtab_size,
        0,
        0,
        1,
        0
    )
    blob = bytearray()
    blob += elf_hdr
    blob += sh_null
    blob += sh_payload
    blob += sh_shstr
    cur_len = len(blob)
    if cur_len < payload_off:
        blob += b'\x00' * (payload_off - cur_len)
    blob += payload_bytes
    cur_len = len(blob)
    if cur_len < shstrtab_off:
        blob += b'\x00' * (shstrtab_off - cur_len)
    blob += shstrtab
    return bytes(blob)

def parse_args():
    ap = argparse.ArgumentParser(description="Verbose carve tool")
    ap.add_argument("input", help="Input JPEG file")
    ap.add_argument("--from-last-eoi", action="store_true", help="Use last EOI occurrence")
    ap.add_argument("--outdir", default="carved_output", help="Output directory")
    ap.add_argument("--make-object-elf", action="store_true", help="Create non-exec ELF object for static analysis")
    ap.add_argument("--force", action="store_true", help="Force writing payload.bin even if no EOI (writes entire file)")
    ap.add_argument("--carve-from-offset", type=int, default=None, help="Force carve starting at this byte offset")
    return ap.parse_args()

def main():
    args = parse_args()
    inp = args.input
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    if not os.path.isfile(inp):
        print(f"[ERROR] Input file not found: {inp}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(inp, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[ERROR] Could not read input file: {e}", file=sys.stderr)
        sys.exit(3)

    print("[i] Input:", os.path.abspath(inp))
    print("[i] Output dir:", outdir)
    print("[i] File size:", len(data), "bytes")
    # quick checks for SOI
    soi_idx = data.find(b'\xff\xd8')
    print("[i] SOI (0xFFD8) first occurrence at:", soi_idx if soi_idx!=-1 else "not found")

    # determine carve start
    carve_start = None
    reason = None
    if args.carve_from_offset is not None:
        if args.carve_from_offset < 0 or args.carve_from_offset >= len(data):
            print("[ERROR] --carve-from-offset is out of range", file=sys.stderr)
            sys.exit(4)
        carve_start = args.carve_from_offset
        reason = f"forced by --carve-from-offset {carve_start}"
    else:
        eoi_idx = find_eoi(data, use_last=args.from_last_eoi)
        print("[i] EOI search:", "last" if args.from_last_eoi else "first")
        print("[i] EOI (0xFFD9) index:", eoi_idx if eoi_idx != -1 else "not found")
        if eoi_idx != -1:
            carve_start = eoi_idx + 2
            reason = f"after EOI at {eoi_idx}"
        else:
            if args.force:
                carve_start = 0
                reason = "--force provided, writing entire file as payload.bin"
            else:
                print("[!] No EOI found and --force not provided. Nothing will be written.", file=sys.stderr)
                print("[!] If you want to write the whole file anyway, re-run with --force.")
                print("[!] Or specify --carve-from-offset <offset> to carve from a specific byte offset.")
                sys.exit(0)

    if carve_start >= len(data):
        print("[i] Carve start is at or beyond EOF. Nothing to write.")
        sys.exit(0)

    trailer = data[carve_start:]
    payload_path = os.path.join(outdir, "payload.bin")
    ok, err = write_file(payload_path, trailer)
    if not ok:
        print(f"[ERROR] Failed to write payload.bin: {err}", file=sys.stderr)
        sys.exit(5)
    print("[+] Wrote payload.bin:", payload_path)
    print("    size:", len(trailer), "bytes")
    print("    sha256:", sha256_hex(trailer))
    print("    carve reason:", reason)

    if args.make_object_elf:
        obj_path = os.path.join(outdir, "payload_as_object.elf")
        try:
            elf_bytes = make_nonexec_elf_object(trailer)
            ok, err = write_file(obj_path, elf_bytes)
            if not ok:
                print(f"[ERROR] Could not write ELF object: {err}", file=sys.stderr)
            else:
                print("[+] Wrote non-executable ELF object:", obj_path)
                print("    size:", len(elf_bytes), "bytes sha256:", sha256_hex(elf_bytes))
        except Exception as e:
            print("[ERROR] Exception while producing ELF object:", e, file=sys.stderr)

    print("[i] Done. Remember: analyze outputs in an isolated sandbox/VM. Do not execute extracted content on hosts.")

if __name__ == "__main__":
    main()
