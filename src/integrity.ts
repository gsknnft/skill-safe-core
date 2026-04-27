/**
 * Source integrity — SHA-256 content hash, resolved URL hash, timestamp.
 *
 * Uses the Web Crypto API (crypto.subtle) which is available in Node 18+
 * and all modern browsers. Zero external dependencies.
 */

export type SourceIntegrity = {
  /** SHA-256 hex digest of the raw markdown bytes. */
  contentHash: string;
  /** SHA-256 hex digest of the resolved URL string, or null if no URL. */
  urlHash: string | null;
  /** Resolved URL at scan time, or null. */
  resolvedUrl: string | null;
  /** ISO 8601 timestamp of when the integrity record was created. */
  scannedAt: string;
  /** Byte length of the content (UTF-8). */
  bytes: number;
  /** Algorithm used. Always "SHA-256" for now. */
  algorithm: "SHA-256";
};

const toHex = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
};

const sha256Hex = async (value: string): Promise<string> => {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return toHex(digest);
};

/**
 * Compute a SourceIntegrity record for a given markdown content string.
 *
 * @param content - Raw markdown bytes (string)
 * @param resolvedUrl - The URL it was fetched from, or null for local files
 */
export const computeContentIntegrity = async (
  content: string,
  resolvedUrl: string | null = null,
): Promise<SourceIntegrity> => {
  const [contentHash, urlHash] = await Promise.all([
    sha256Hex(content),
    resolvedUrl !== null ? sha256Hex(resolvedUrl) : Promise.resolve(null),
  ]);

  const encoded = new TextEncoder().encode(content);

  return {
    contentHash,
    urlHash,
    resolvedUrl,
    scannedAt: new Date().toISOString(),
    bytes: encoded.length,
    algorithm: "SHA-256",
  };
};

/**
 * Returns a compact SRI-style string: sha256-<base64> for embedding in
 * manifests or lock files. Uses URL-safe base64 (no padding).
 */
export const toSriString = (integrity: SourceIntegrity): string => {
  // Convert hex to bytes, then base64url
  const hex = integrity.contentHash;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  // btoa works in Node 18+ and browsers
  const b64 = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `sha256-${b64}`;
};
