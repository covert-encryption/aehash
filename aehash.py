"""A simple but slower AEhash implementation."""
# pip install cryptography

from hashlib import sha512
from sys import argv, exit, stderr
from unicodedata import normalize

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aehash(password: bytes, salt: bytes, mem=500, ops=10) -> bytes:
    """Derive a 32-byte hash for (password, salt) using mem MiB and ops iterations."""
    if mem <= 0 or ops < 2 or mem * ops > 100000:
        raise ValueError(f"Invalid cost parameters {mem=} {ops=}")
    nonce = sha(salt)[:12]
    key = sha(password)[:32]
    size = mem << 20  # MiB
    buf = bytes(size)  # Initially all zeroes
    for i in range(ops):
        # AES256-GCM, returns size bytes ciphertext + 16 bytes GCM tag
        buf = AESGCM(key).encrypt(nonce, buf[:size], None)
        key = buf[-32:]  # 16 encrypted bytes + 16 bytes gcm tag
    # Hash the final key for output
    return sha(key)[:32]


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
