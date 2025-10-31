#!/usr/bin/env python3
# AES-128-CBC decryption example
# Key, IV from NIST SP 800-38A Appendix F.2.1 (CBC-AES128.Encrypt)
# pip install pycryptodome

from Crypto.Cipher import AES
import binascii

# ----------------------------------------------------
# 🔐 ciphertext 여기에 넣으세요!
# 예: 문제에서 준 16진수 (hex) 문자열 그대로
CIPHERTEXT_HEX = "933fe22ede6000f0d403b68afc403638bbd69fc36c0b320c9f81edd76479fdc80c4a4fe6d09eb89c8ed2ac72dd4507b8"
# ----------------------------------------------------

# NIST 표준 Key / IV
KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
IV_HEX  = "000102030405060708090a0b0c0d0e0f"

# hex → bytes
ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)
key = binascii.unhexlify(KEY_HEX)
iv  = binascii.unhexlify(IV_HEX)

# AES-CBC 복호화
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext_padded = cipher.decrypt(ciphertext)

# PKCS#7 언패딩
def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        return data  # 패딩이 없거나 이상하면 그대로 반환
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]

plaintext = pkcs7_unpad(plaintext_padded)

# 결과 출력
print("Ciphertext (hex):", CIPHERTEXT_HEX)
print("Plaintext (hex):", binascii.hexlify(plaintext).decode())

try:
    print("Plaintext (utf-8):", plaintext.decode('utf-8'))
except UnicodeDecodeError:
    print("Plaintext (utf-8): 디코딩 불가 (바이너리 데이터일 수 있음)")
