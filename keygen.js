export async function decode(options = {}) {
  const { licenseFile } = options
  if (!licenseFile) {
    throw new Error('license file is required')
  }

  const encodedPayload = licenseFile.replace(/-----(?:BEGIN|END) LICENSE FILE-----\n?/g, '')

  let decodedPayload
  try {
    decodedPayload = atob(encodedPayload)
  } catch (e) {
    console.error(e)

    throw new Error('failed to decode license file')
  }

  let payload
  try {
    payload = JSON.parse(decodedPayload)
  } catch (e) {
    console.error(e)

    throw new Error('failed to parse license file')
  }

  const { enc, sig, alg } = payload
  if (alg !== 'aes-256-gcm+ed25519') {
    throw new Error(`license file algorithm is not supported: ${alg}`)
  }

  return { enc, sig, alg }
}

export async function verify(options = {}) {
  const { publicKey, enc, sig } = options
  if (!publicKey) {
    throw new Error('public key must be a DER-encoded Ed25519 verify key')
  }

  const publicKeyBytes = new Uint8Array(publicKey.match(/.{2}/g).map(byte => parseInt(byte, 16)))
  const signatureBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0))
  const dataBytes = new TextEncoder().encode(`license/${enc}`)

  let cryptoKey
  try {
    cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519', public: true },
      true,
      ['verify'],
    )
  } catch (e) {
    console.error(e)

    throw new Error('failed to import public key')
  }

  let isValid = false
  try {
    isValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      cryptoKey,
      signatureBytes,
      dataBytes,
    )
  } catch (e) {
    console.error(e)

    throw new Error('failed to verify license file signature')
  }

  if (!isValid) {
    throw new Error('license file signature is invalid')
  }

  return true
}

export async function decrypt(options = {}) {
  const { enc, licenseKey } = options
  if (!licenseKey) {
    throw new Error('license file is required')
  }

  const [ciphertext, iv, tag] = enc.split('.')

  let digest
  try {
    digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(licenseKey),
    )
  } catch (e) {
    console.error(e)

    throw new Error('failed to generate license key digest')
  }

  let aesKey
  try {
    aesKey = await crypto.subtle.importKey(
      'raw',
      digest,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )
  } catch (e) {
    console.error(e)

    throw new Error('failed to import license key digest')
  }

  let decrypted
  try {
    decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)),
        additionalData: new Uint8Array(),
        tagLength: 128
      },
      aesKey,
      Uint8Array.from(
        atob(ciphertext) + atob(tag),
        c => c.charCodeAt(0),
      ),
    )
  } catch (e) {
    console.error(e)

    throw new Error('failed to decrypt license file')
  }

  const plaintext = new TextDecoder().decode(decrypted)

  const { meta, data, included } = JSON.parse(plaintext)
  const { issued, expiry } = meta
  if (new Date(issued).getTime() > Date.now()) {
    throw new Error('system clock is desynced')
  }

  if (expiry && (new Date(expiry).getTime() < Date.now())) {
    throw new Error('license file is expired')
  }

  return { meta, data, included }
}
