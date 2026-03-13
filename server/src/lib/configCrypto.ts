import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const ENC_PREFIX = "enc:";

// Fixed salt — not secret, just ensures domain separation from other HKDF uses
const HKDF_SALT = Buffer.from("vigil-notifications-v1");
const HKDF_INFO = Buffer.from("aes-256-gcm-key");

/**
 * Derives the AES-256-GCM key from NOTIFICATIONS_ENCRYPTION_KEY using HKDF-SHA256.
 *
 * NOTIFICATIONS_ENCRYPTION_KEY must be a securely generated random value, e.g.:
 *   openssl rand -hex 32
 *
 * Using a short or memorable passphrase is unsafe — HKDF provides no iteration
 * count, so offline brute-force against a weak input remains cheap.
 */
function getKey(): Buffer | null {
  const raw = process.env["NOTIFICATIONS_ENCRYPTION_KEY"];
  if (!raw) return null;
  return Buffer.from(hkdfSync("sha256", raw, HKDF_SALT, HKDF_INFO, 32));
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * If NOTIFICATIONS_ENCRYPTION_KEY is not set, returns the plaintext unchanged
 * (allows the app to run without encryption configured, with a warning).
 */
export function encryptConfig(plaintext: string): string {
  const key = getKey();
  if (!key) {
    return plaintext;
  }

  const iv = randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return (
    ENC_PREFIX +
    [iv, authTag, encrypted].map((b) => b.toString("base64")).join(":")
  );
}

/**
 * Decrypts a value produced by encryptConfig.
 * If the value does not start with "enc:" it is returned as-is (plaintext / legacy row).
 * Throws if the key is missing but a ciphertext is present.
 */
export function decryptConfig(stored: string): string {
  if (!stored.startsWith(ENC_PREFIX)) {
    return stored; // plaintext or legacy unencrypted row
  }

  const key = getKey();
  if (!key) {
    throw new Error(
      "NOTIFICATIONS_ENCRYPTION_KEY is required to decrypt stored notification configs"
    );
  }

  const parts = stored.slice(ENC_PREFIX.length).split(":");
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted config format");
  }

  const [ivB64, authTagB64, encryptedB64] = parts as [string, string, string];
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const encrypted = Buffer.from(encryptedB64, "base64");

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(encrypted).toString("utf8") + decipher.final("utf8");
}
