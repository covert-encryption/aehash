from hashlib import sha512
from sys import argv, exit, stderr
from unicodedata import normalize

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aehash(password, salt, mem=10, ops=2):
    if mem <= 0 or ops <= 0 or mem * ops > 100000:
        raise ValueError(f"Invalid cost parameters {mem=} {ops=}")
    nonce = sha(salt)[:12]
    key = sha(password)[:32]
    size = mem << 20  # MiB
    buf = bytes(size)
    for i in range(ops):
        buf = AESGCM(key).encrypt(nonce, buf[:size], None)
        key = buf[-32:]  # 16 encrypted bytes + 16 bytes gcm tag
    return key


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
