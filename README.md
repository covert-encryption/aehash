# Authenticated Encryption Hasher

## Introduction

While [Argon2](https://github.com/P-H-C/phc-winner-argon2) and [Scrypt](http://www.tarsnap.com/scrypt.html) are great, browsers don't support them, or any other modern password hashing. There are only Javascript and Web Assembly implementations available, but unfortunately any hashing performed even with the fastest implementations is about ten times slower than native code, while both are still single threaded. Cracking passwords, employing all CPU cores, is then roughly 100 times faster than what it takes for a user to have his password hashed in a browser on the same desktop PC.

[Balloon hashing](https://github.com/henrycg/balloon) is another memory-hard scheme, interesting in that it is really simple and uses a standard hash function like SHA-512 for all its operations, paving road to efficient browser implementation. We did experiment with this, but since only 64 bytes are hashed at a time, Javascript remains a major bottle neck. Modifying the algorithm to hash more at once is also problematic, as then each operation takes longer reading data but still writes only the 64-byte hash, weakening the security of memory mixing.

Browsers offer only a limited set of cryptographic primitives in WebCrypto/Subtle API. and it turns out that AES encryption is one that should work well for password hashing while running at the same speed as any native code. Using multiple cores offers only moderate speedup with this algorithm and as far as I can tell, there are no existing threaded implementations of it. The advantage of encryption over hashing is that all of the buffer memory can be rewritten on each operation. Given that the cipher itself is secure, this cannot be reversed. Further, authenticated encryption algorithms calculate a tag that acts as a hash or checksum for the whole ciphertext produced.

## Methods

We propose a novel hashing algorithm dubbed **AEhash** after its dependence on authenticated encryption. The implementation is based on AES256-GCM but the hashing can be performed similarly with ChaCha-Poly1305 if that ever becomes available in browsers, with the benefit of being fast also on mobile devices that do not have hardware acceleration for fast AES, like all Intel and AMD CPUs nowadays do.

This algorithm seems quite secure, as it relies on the security of the block cipher and not on any custom bit fiddling. However, we are now presenting this for review by a wider audience, asking everyone to look for any possible vulnerabilities. Without proper review, we cannot consider it safe for general use.

## Performance and parameters

Implementations in several languages are presented for comparison. One iteration over 1 GB buffer takes about half a second with each of these implementations, with highly optimized C and Python being equal and only moderately faster than Javascript or the less optimized Python implementation.

AEhash offers two easily tunable parameters: the amount of memory to use, and the number of iterations taken. The duration is relative to both of these. For instance, 50 MB * 100 ops takes the same time as 1000 MB and 5 ops. AEhash allows for more precise tuning of both memory and time than Argon2 or Scrypt do.

Most implementations are expected to require twice the amount of memory specified, or in case of garbage-collected languages possibly even many times as much. In Javascript this is impossible to avoid, but we present C and Python implementations based on libsodium that avoid any extra buffers being created by doing the encryption in place.

## The Algorithm

The salt and the password are both SHA-512 hashed, and of each hash its initial 12 and 32 bytes, respectively, are used as encryption nonce and key, for the initial round of AES-GCM, over the whole buffer. After each round the key is replaced by the final 32 bytes of the AEAD output, meaning the last 16 bytes of ciphertext followed by a 16-byte authentication tag. Once `ops` iterations are completed, the 32-byte key is returned. That is it, quite simple.

Python:
```python
def aehash(password, salt, mem=500, ops=10):
    size = mem << 20  # mem MiB
    # Inputs are SHA-512 hashed and truncated to 12 and 32 bytes
    nonce = sha(salt)[:12]
    key = sha(password)[:32]
    buf = bytes(size)     # Initially all zeroes
    for i in range(ops):
        # AES256-GCM, returns size bytes ciphertext + 16 bytes GCM tag
        buf = aes(buf[:size], None, nonce, key)
        key = buf[-32:]   # 16 encrypted bytes + GCM tag
    # Hash the final key for output
    return sha(key)[:32]
```

Each round reads and writes the entire buffer with data that cannot be predicted without holding all the bytes output by the previous round. Preserving memory-hardness requires that passes cannot be run in parallel, which is accomplished because the next round cannot begin without the encryption key extracted from the authentication tag of the previous round. That tag depends on every byte of the ciphertext produced, so it cannot be known in advance.


Javascript:
```javascript
async function aehash(password, salt, mem, ops) {
  const size = mem << 20  // mem MiB
  const iv = (await crypto.subtle.digest("SHA-512", salt)).slice(0, 12)
  let key = (await crypto.subtle.digest("SHA-512", password)).slice(0, 32)
  let buf = new ArrayBuffer(size)  // Initially all zeroes
  while (ops--) {
    const bufview = new DataView(buf, 0, size)
    const aeskey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"])
    buf = await crypto.subtle.encrypt({name: "AES-GCM", iv}, aeskey, bufview)
    key = buf.slice(size - 16, size + 16)  // 16 bytes ciphertext, 16 bytes GCM tag
  }
  // Hash the final key for output
  return (await crypto.subtle.digest("SHA-512", key)).slice(0, 32)
}
```

C:
```c
int aehash(uint8_t* hash, uint8_t const* pw, size_t pwlen, uint8_t const* salt, size_t saltlen, unsigned mem, unsigned ops) {
  size_t size = (size_t)mem << 20;
  unsigned long long outsize;
  uint8_t nonce[64], key[64];  // 64 to fit an entire SHA-512
  uint8_t* buf = calloc(1, size + 16);  // 16 extra for GCM tag
  if (!buf) return 1;
  crypto_hash_sha512(nonce, salt, saltlen);
  crypto_hash_sha512(key, pw, pwlen);
  while (ops--) {
    // In-place encryption, appends the 16 byte tag after size bytes of ciphertext
    crypto_aead_aes256gcm_encrypt(buf, &outsize, buf, size, NULL, 0, NULL, nonce, key);
    memcpy(key, buf + size - 16, 32);
  }
  free(buf);
  memcpy(hash, key, 32);
  return 0;
}
```

See the files in this repository for more complete examples. These snippets are only to illustrate the algorithm.


## Design Choices

The final key that would be used on the next round is hashed for output. Using the key rather than hashing the whole buffer is much faster, allowing for one or two more ops in the time that SHA-512 would take. Hashing is a bit moot because the key already depends on all bytes of ciphertext produced on the final round. If only some bytes of the ciphertext were used, and not the tag, an attacker could encrypt only those bytes, skipping most of the final iteration.

SHA-512 of all inputs and the output provides additional security with negligible computational cost or added complexity of implementation. In particular, the output hashing avoids revealing the intermediate rounds' encryption keys to an attacker who can manipulate the ops paramater and obtain the hashes created for a particular but unknown pair of (password, salt).

The reuse of a nonce over all rounds may concern some. However, there is no conceivable reason why the key would ever be the same in any successive rounds, thus no changes in nonce are needed. Another related concern is that both the key and and the nonce may be identical when the same password is hashed again with the same nonce. This obviously produces the exact same process each time, and the same hash output, as is expected. In a normal setting the security of AEAD ciphers is completely destroyed if (key, nonce) are both reused. However, this is only a problem when the adversary has access to the ciphertext, which is not possible here, given that the internal buffer and keys are never revealed.

Please file an issue if you think that anything of the above is wrong, or if you find any other problem with this algorithm.
