import hashlib
import os
import struct
import sys

from .i18n import tr

try:
    from Crypto.Cipher import AES
except ImportError:
    print(tr('pycryptodome_missing'))
    sys.exit(1)


try:
    import tgcrypto
except ImportError:
    tgcrypto = None


def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if tgcrypto is not None:
        return tgcrypto.ige256_decrypt(data, key, iv)
    ecb = AES.new(key, AES.MODE_ECB)
    x, y = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        d = ecb.decrypt(bytes(a ^ b for a, b in zip(c, y)))
        p = bytes(a ^ b for a, b in zip(d, x))
        out += p
        x, y = c, p
    return bytes(out)


def create_local_key(passcode: bytes, salt: bytes) -> bytes:
    h = hashlib.sha512(salt + passcode + salt).digest()
    iters = 1 if not passcode else 100_000
    return hashlib.pbkdf2_hmac('sha512', h, salt, iters, dklen=256)


def create_legacy_local_key(passcode: bytes, salt: bytes) -> bytes:
    iters = 4 if not passcode else 4000
    return hashlib.pbkdf2_hmac('sha1', passcode, salt, iters, dklen=256)


def prepare_aes_oldmtp(key256: bytes, msg_key: bytes, x: int = 8):
    sha_a = hashlib.sha1(msg_key + key256[x:x + 32]).digest()
    sha_b = hashlib.sha1(key256[32 + x:48 + x] + msg_key + key256[48 + x:64 + x]).digest()
    sha_c = hashlib.sha1(key256[64 + x:96 + x] + msg_key).digest()
    sha_d = hashlib.sha1(msg_key + key256[96 + x:128 + x]).digest()
    aes_key = sha_a[:8] + sha_b[8:20] + sha_c[4:16]
    aes_iv = sha_a[8:20] + sha_b[:8] + sha_c[16:20] + sha_d[:8]
    return aes_key, aes_iv


def decrypt_local(local_key: bytes, blob: bytes):
    if len(blob) <= 16 or (len(blob) & 0x0F):
        return None
    msg_key, enc = blob[:16], blob[16:]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key, x=8)
    try:
        dec = ige256_decrypt(enc, aes_key, aes_iv)
    except Exception:
        return None
    if hashlib.sha1(dec).digest()[:16] != msg_key:
        return None
    data_len = struct.unpack('<I', dec[:4])[0]
    if data_len < 4 or data_len > len(dec):
        return None
    return dec[4:data_len]


def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    ecb = AES.new(key, AES.MODE_ECB)
    x, y = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        p = data[i:i + 16]
        c = bytes(a ^ b for a, b in zip(
            ecb.encrypt(bytes(u ^ v for u, v in zip(p, x))), y))
        out += c
        x, y = c, p
    return bytes(out)


def encrypt_local(local_key: bytes, payload: bytes) -> bytes:
    full = struct.pack('<I', 4 + len(payload)) + payload
    if len(full) % 16:
        full += os.urandom(16 - len(full) % 16)
    msg_key = hashlib.sha1(full).digest()[:16]
    aes_key, aes_iv = prepare_aes_oldmtp(local_key, msg_key, x=8)
    return msg_key + ige256_encrypt(full, aes_key, aes_iv)


def open_tdef(path: str, local_key: bytes):
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None
    if len(raw) < 4 + 64 + 48 + 16 or raw[:4] != b'TDEF':
        return None
    salt = raw[4:68]
    key = hashlib.sha256(local_key[:128] + salt[:32]).digest()
    iv = hashlib.sha256(local_key[128:] + salt[32:64]).digest()[:16]
    body = raw[68:]
    usable = len(body) - (len(body) % 16)
    if usable < 48:
        return None
    ctr = AES.new(key, AES.MODE_CTR, nonce=b'',
                  initial_value=int.from_bytes(iv, 'big'))
    dec = ctr.decrypt(body[:usable])
    if hashlib.sha256(local_key + salt + dec[:16]).digest() != dec[16:48]:
        return None
    return dec[48:]
