async function aehash(password, salt, mem=500, ops=10) {
  if (mem < 1 || mem > 10000) throw new Error('Invalid mem argument')
  if (ops < 2) throw new Error('Invalid ops argument')
  const size = mem << 20  // mem MiB
  const iv = (await crypto.subtle.digest("SHA-512", salt)).slice(0, 12)
  let key = (await crypto.subtle.digest("SHA-512", password)).slice(0, 32)
  let buf = new ArrayBuffer(size)  // Initially all zeroes
  while (ops--) {
    const bufview = new DataView(buf, 0, size)
    buf = null  // Allow garbage collection
    const aeskey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"])
    buf = await crypto.subtle.encrypt({name: "AES-GCM", iv}, aeskey, bufview)
    key = buf.slice(size - 16, size + 16)  // 16 encrypted bytes + 16 bytes GCM tag
  }
  // Hash the final key for output
  return (await crypto.subtle.digest("SHA-512", key)).slice(0, 32)
}

// String to ArrayBuffer conversion with Unicode normalisation
const encode = str => new TextEncoder().encode(str.normalize('NFKC'))

// Hash password, print hex digest and ArrayBuffer
console.log("Calculating hash...")
const hash = await aehash(encode("pass"), encode("salt"))
const hexhash = [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2, "0")).join("")
console.log(hexhash, hash)
