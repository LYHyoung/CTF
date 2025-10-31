#!/usr/bin/env python3
# Pure-Python AES-128-CBC Decrypt (no external packages)
# Default Key/IV: NIST SP 800-38A Appendix F.2.1 (CBC-AES128.Encrypt)

import binascii

# =========[ ① 여기에 문제의 암호문(hex) 넣으세요 ]=========
CIPHERTEXT_HEX = "933fe22ede6000f0d403b68afc403638bbd69fc36c0b320c9f81edd76479fdc80c4a4fe6d09eb89c8ed2ac72dd4507b8"  # <--- 교체
# ==========================================================

# NIST SP 800-38A F.2.1 Key / IV (AES-128)
KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
IV_HEX  = "000102030405060708090a0b0c0d0e0f"

# ---------------- AES Tables ----------------
s_box = [
    99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
   202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
   183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
     4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
     9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
    83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
   208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
    81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
   205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
    96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
   224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
   231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
   186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
   112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
   225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
   140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22
]
inv_s_box = [
    82,  9,106,213, 48, 54,165, 56,191, 64,163,158,129,243,215,251,
   124,227, 57,130,155, 47,255,135, 52,142, 67, 68,196,222,233,203,
    84,123,148, 50,166,194, 35, 61,238, 76,149, 11, 66,250,195, 78,
     8, 46,161,102, 40,217, 36,178,118, 91,162, 73,109,139,209, 37,
   114,248,246,100,134,104,152, 22,212,164, 92,204, 93,101,182,146,
   108,112, 72, 80,253,237,185,218, 94, 21, 70, 87,167,141,157,132,
   144,216,171,  0,140,188,211, 10,247,228, 88,  5,184,179, 69,  6,
   208, 44, 30,143,202, 63, 15,  2,193,175,189,  3,  1, 19,138,107,
    58,145, 17, 65, 79,103,220,234,151,242,207,206,240,180,230,115,
   150,172,116, 34,231,173, 53,133,226,249, 55,232, 28,117,223,110,
    71,241, 26,113, 29, 41,197,137,111,183, 98, 14,170, 24,190, 27,
   252, 86, 62, 75,198,210,121, 32,154,219,192,254,120,205, 90,244,
    31,221,168, 51,136,  7,199, 49,177, 18, 16, 89, 39,128,236, 95,
    96, 81,127,169, 25,181, 74, 13, 45,229,122,159,147,201,156,239,
   160,224, 59, 77,174, 42,245,176,200,235,187, 60,131, 83,153, 97,
    23, 43,  4,126,186,119,214, 38,225,105, 20, 99, 85, 33, 12,125
]
Rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

# --------------- Helpers ---------------
def xtime(a):  # multiply by 2 in GF(2^8)
    a <<= 1
    return ((a & 0x100) ^ 0x1B) & 0xFF if (a & 0x100) else (a & 0xFF)

def gf_mul(a, b):  # generic GF(2^8) multiply
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF)
        if hi:
            a ^= 0x1B
        b >>= 1
    return res & 0xFF

def sub_word(word):
    return ((s_box[(word >> 24) & 0xFF] << 24) |
            (s_box[(word >> 16) & 0xFF] << 16) |
            (s_box[(word >>  8) & 0xFF] <<  8) |
            (s_box[(word >>  0) & 0xFF]      ))

def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def bytes_to_state(block16):
    # AES uses column-major: state[r][c]
    return [[block16[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(state):
    return bytes(state[r][c] & 0xFF for c in range(4) for r in range(4))

def add_round_key(state, round_key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = inv_s_box[state[r][c]]

def inv_shift_rows(state):
    # row 0: no shift
    # row 1: right shift by 1
    # row 2: right shift by 2
    # row 3: right shift by 3
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def inv_mix_columns(state):
    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))
        state[0][c] = (gf_mul(a0,0x0e) ^ gf_mul(a1,0x0b) ^ gf_mul(a2,0x0d) ^ gf_mul(a3,0x09)) & 0xFF
        state[1][c] = (gf_mul(a0,0x09) ^ gf_mul(a1,0x0e) ^ gf_mul(a2,0x0b) ^ gf_mul(a3,0x0d)) & 0xFF
        state[2][c] = (gf_mul(a0,0x0d) ^ gf_mul(a1,0x09) ^ gf_mul(a2,0x0e) ^ gf_mul(a3,0x0b)) & 0xFF
        state[3][c] = (gf_mul(a0,0x0b) ^ gf_mul(a1,0x0d) ^ gf_mul(a2,0x09) ^ gf_mul(a3,0x0e)) & 0xFF

def key_expansion_128(key16):
    # returns list of 11 round keys, each as 4x4 state
    Nk, Nb, Nr = 4, 4, 10
    w = [0]*44
    # pack key into 4 words
    for i in range(Nk):
        w[i] = ((key16[4*i] << 24) | (key16[4*i+1] << 16) |
                (key16[4*i+2] << 8) | key16[4*i+3])
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ (Rcon[i//Nk] << 24)
        w[i] = w[i-Nk] ^ temp
    # convert to 11 round keys (each 16 bytes -> 4x4 state)
    round_keys = []
    for r in range(Nr+1):
        block = bytearray(16)
        for c in range(4):
            word = w[4*r + c]
            block[4*c + 0] = (word >> 24) & 0xFF
            block[4*c + 1] = (word >> 16) & 0xFF
            block[4*c + 2] = (word >>  8) & 0xFF
            block[4*c + 3] = (word      ) & 0xFF
        round_keys.append(bytes_to_state(block))
    return round_keys

def aes128_decrypt_block(block16, round_keys):
    # AES-128 decryption: Nr=10
    Nr = 10
    state = bytes_to_state(block16)
    add_round_key(state, round_keys[Nr])
    for rnd in range(Nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[rnd])
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)

def pkcs7_unpad(data, block_size=16):
    if not data or len(data) % block_size != 0:
        return data  # 안전하게 그대로
    pad = data[-1]
    if pad < 1 or pad > block_size:
        return data
    if data[-pad:] != bytes([pad])*pad:
        return data
    return data[:-pad]

def aes128_cbc_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("AES-128 requires 16-byte key and 16-byte IV.")
    if len(ct) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes.")
    round_keys = key_expansion_128(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        plain_block = aes128_decrypt_block(block, round_keys)
        # CBC XOR with previous ciphertext (or IV for first block)
        out.extend(bytes(a ^ b for a, b in zip(plain_block, prev)))
        prev = block
    return bytes(out)

def main():
    key = binascii.unhexlify(KEY_HEX)
    iv  = binascii.unhexlify(IV_HEX)
    ct  = binascii.unhexlify(CIPHERTEXT_HEX)

    pt_padded = aes128_cbc_decrypt(ct, key, iv)
    pt = pkcs7_unpad(pt_padded)

    print("Ciphertext (hex):", CIPHERTEXT_HEX)
    print("Plaintext  (hex):", binascii.hexlify(pt).decode())

    try:
        print("Plaintext (utf-8):", pt.decode("utf-8"))
    except UnicodeDecodeError:
        print("Plaintext (utf-8): 디코딩 불가 (바이너리 데이터일 수 있음)")

    # flag 자동 감지(있으면 출력)
    s = pt.decode("latin1", errors="ignore")
    if "flag{" in s:
        start = s.find("flag{")
        end = s.find("}", start)
        if end != -1:
            print("Detected flag     :", s[start:end+1])

if __name__ == "__main__":
    main()
