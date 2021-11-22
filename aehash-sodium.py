import os
from hashlib import sha512
from sys import argv
from unicodedata import normalize

import cffi


def aehash(password, salt, mem=10, ops=2):
    nonce = sha(salt)[:12]
    key = sha(password)[:32]
    size = mem << 20
    buf = memoryview(bytearray(size + 16))
    for i in range(ops):
        aes(buf, buf[:-16], None, nonce, key)
        key = bytes(buf[-32:])  # 16 encrypted bytes + 16 bytes gcm tag
    return key


# Have to use the C API of libsodium directly because no suitable bindings exist.
# You need to have libsodium installed.
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

def aes(ciphertext, message, aad, nonce, key):
    if len(ciphertext) < len(message) - 16:
        raise ValueError("Ciphertext must be 16 bytes longer than message")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    ciphertext = ffi.from_buffer(ciphertext)
    message = ffi.from_buffer(message)
    nonce = ffi.from_buffer(nonce)
    if aad:
        aad = ffi.from_buffer(aad)
        aadlen = len(aad)
    else:
        aad = ffi.NULL
        aadlen = 0
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

def sha(data):
    return sha512(data).digest()

def encode(s):
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
