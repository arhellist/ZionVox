/**
 * Учебный слой «шифрование по умолчанию» для аудита (браузер, Web Crypto API).
 * Это НЕ полная копия прод-протокола: в продукте добавляются X25519/сессии/версии.
 *
 * Показано намеренно: симметричное AES-256-GCM — стандартный примитив, чтобы аудитор
 * увидел реальный вызов crypto.subtle, а не пустую заглушку.
 */

const AUDIT_AES_GCM = "AES-GCM";
const AUDIT_KEY_BITS = 256;

function toB64(u8: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Импорт сырого 32-байтного ключа как AES-GCM (ключ в примере — сессионный, не логируйте). */
export async function auditImportAesGcmKey(raw32: Uint8Array): Promise<CryptoKey> {
  if (raw32.length !== 32) {
    throw new Error("audit: AES key material must be 32 bytes for this demo");
  }
  // Приведение: TS 5.6 строже к ArrayBufferLike vs ArrayBuffer у Uint8Array
  return crypto.subtle.importKey("raw", raw32 as BufferSource, { name: AUDIT_AES_GCM, length: AUDIT_KEY_BITS }, false, [
    "encrypt",
    "decrypt"
  ]);
}

export interface AuditSealedPacket {
  ivB64: string;
  ciphertextB64: string;
}

/**
 * Шифрование UTF-8 строки AES-256-GCM. IV случайный на каждое сообщение.
 * Открытый текст в сеть не уходит — только iv + ciphertext (base64).
 */
export async function auditSealUtf8WithAesGcm(plain: string, key: CryptoKey): Promise<AuditSealedPacket> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plain);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: AUDIT_AES_GCM, iv: iv as BufferSource }, key, data)
  );
  return { ivB64: toB64(iv), ciphertextB64: toB64(ct) };
}

export async function auditOpenUtf8WithAesGcm(packet: AuditSealedPacket, key: CryptoKey): Promise<string> {
  const iv = fromB64(packet.ivB64);
  const raw = fromB64(packet.ciphertextB64);
  const plainBuf = await crypto.subtle.decrypt(
    { name: AUDIT_AES_GCM, iv: iv as BufferSource },
    key,
    raw as BufferSource
  );
  return new TextDecoder().decode(plainBuf);
}
