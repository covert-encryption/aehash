// gcc aehash.c -l sodium -o aehash

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int aehash(uint8_t* hash, uint8_t const* pw, size_t pwlen, uint8_t const* salt, size_t saltlen, unsigned mem, unsigned ops) {
  size_t size = mem << 20ull;
  unsigned long long outsize;
  uint8_t nonce[64], key[64];  // 64 to fit an entire SHA-512
  uint8_t* buf = calloc(1, size + 16);
  if (!buf) return 1;
  crypto_hash_sha512(nonce, salt, saltlen);
  crypto_hash_sha512(key, pw, pwlen);
  while (ops--) {
    crypto_aead_aes256gcm_encrypt(buf, &outsize, buf, size, NULL, 0, NULL, nonce, key);
    memcpy(key, buf + size - 16, 32);
  }
  free(buf);
  memcpy(hash, key, 32);
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 5) {
    fprintf(stderr, "Usage: %s PASSWORD SALT MEM OPS\n\n  MEM is in megabytes, OPS is the number of iterations.\n"
      "  The duration is relative to MEM * OPS.\n", argv[0]);
    return 1;
  }
  void const *pass = argv[1], *salt = argv[2];
  unsigned mem = atoi(argv[3]), ops = atoi(argv[4]);
  if (!mem || !ops || (uint64_t)mem * ops > 100000) { fprintf(stderr, "Invalid MEM/OPS arguments.\n"); return 1; }

  // Hash and print in hex
  uint8_t hash[32];
  int ret = aehash(hash, pass, strlen(pass), salt, strlen(salt), mem, ops);
  if (ret) { fprintf(stderr, "Unable to allocate memory\n"); return 1; }
  for (unsigned i = 0; i < 32; ++i) printf("%02x", hash[i]);
  printf("\n");
}
