async function aehash(password, salt, mem, ops) {
  if (mem < 1 || mem > 10000) throw new Error('Invalid mem argument')
  if (ops < 1) throw new Error('Invalid ops argument')
  const size = mem << 20  // mem MiB
  const iv = (await crypto.subtle.digest("SHA-512", salt)).slice(0, 12)
  let key = (await crypto.subtle.digest("SHA-512", password)).slice(0, 32)
  let buf = new ArrayBuffer(size)
  while (ops--) {
    const bufview = new DataView(buf, 0, size)
    buf = null  // Allow garbage collection
    const aeskey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"])
    buf = await crypto.subtle.encrypt({name: "AES-GCM", iv}, aeskey, bufview)
    key = buf.slice(size - 16, size + 16)
  }
  return key
}

// String to ArrayBuffer conversion with Unicode normalisation
const encode = str => new TextEncoder().encode(str.normalize('NFKC'))

// Hash password, print hex digest
const hash = await aehash(encode("pass"), encode("salt"), 500, 30)
console.log("Hash", [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2, "0")).join(""))
