"""An optimized Python implementation based on sodium."""
# You need to have the C library libsodium installed

import os
from hashlib import sha512
from sys import argv, stderr
from typing import Optional
from unicodedata import normalize

import cffi


def aehash(password: bytes, salt: bytes, mem=500, ops=10) -> bytes:
    """Derive a 32-byte hash for (password, salt) using mem MiB and ops iterations."""
    if mem <= 0 or ops < 2 or mem * ops > 100000:
        raise ValueError(f"Invalid cost parameters {mem=} {ops=}")
    nonce = sha(salt)[:12]
    key = sha(password)[:32]
    size = mem << 20
    buf = memoryview(bytearray(size + 16))  # Initially all zeroes read-write buffer
    for i in range(ops):
        # AES256-GCM in-place encryption of size bytes. Adds GCM tag at the end.
        aes(buf, buf[:-16], None, nonce, key) 
        key = bytes(buf[-32:])  # 16 encrypted bytes + 16 bytes GCM tag
    # Hash the final key for output
    return sha(key)[:32]


# Have to use the C API of libsodium directly because no suitable bindings exist.
ffi = cffi.FFI()
ffi.cdef(R"""
int crypto_aead_aes256gcm_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub,
    const unsigned char *k
);
""")
lib = ffi.dlopen("libsodium" if os.name == "nt" else "sodium")

def aes(ciphertext: bytes, message: bytes, aad: Optional[bytes], nonce: bytes, key: bytes) -> int:
    if len(ciphertext) < len(message) - 16:
        raise ValueError("Ciphertext must be 16 bytes longer than message")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    ciphertext = ffi.from_buffer(ciphertext)
    message = ffi.from_buffer(message)
    nonce = ffi.from_buffer(nonce)
    aadlen, aad = (len(aad), ffi.from_buffer(aad)) if aad else (0, ffi.NULL)
    outsize = ffi.new("unsigned long long *")
    # According to docs it always returns 0
    lib.crypto_aead_aes256gcm_encrypt(
        ciphertext,
        outsize,
        message,
        len(message),
        aad,
        aadlen,
        ffi.NULL,
        nonce,
        key,
    )
    return outsize

def sha(data: bytes) -> bytes:
    return sha512(data).digest()

def encode(s: str) -> bytes:
    """Encode text into bytes with Unicode normalization."""
    return normalize("NFKC", s).encode()

def main():
    try:
        if len(argv) != 5:
            raise ValueError(
                f"Usage: {argv[0]} PASSWORD SALT MEM OPS\n\n"
                "  MEM is in megabytes, OPS is the number of iterations.\n"
                "  The duration is relative to MEM * OPS."
            )
        pw, salt = encode(argv[1]), encode(argv[2])
        mem, ops = int(argv[3]), int(argv[4])
        print(aehash(pw, salt, mem, ops).hex())
    except ValueError as e:
        stderr.write(f"{e}\n")
        return 1

if __name__ == "__main__":
    exit(main() or 0)
