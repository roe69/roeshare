// End-to-end encryption helpers (WebCrypto, AES-256-GCM). The key is generated
// in the browser, never sent to the server, and shared only via the URL fragment
// (#key), which browsers never transmit. Files are encrypted per record (one per
// upload chunk): each record is [12-byte random IV][ciphertext+16-byte GCM tag].
//
// H-1: two record formats coexist, disambiguated per-file by the (unencrypted)
// `aadVersion` the server hands back alongside a share's file list (see
// files.e2e_aad_version in src/db.js). Legacy records (aadVersion 0) are
// self-authenticated only - each record's GCM tag proves ITS OWN plaintext
// was not altered, but says nothing about its position: swapping two
// same-length records (two chunks of the same file, or even a record from a
// different file/share under a key an attacker also controls) is not
// detected on decrypt. Current records (aadVersion 1) additionally bind
// purpose+file+position via AAD (see recordAad below), mirroring
// src/lib/filecrypt.js's aadV2 - so cross-record splicing is also detected,
// not just per-record tampering.

export const IV_LEN = 12;
export const TAG_LEN = 16;
export const ENC_OVERHEAD = IV_LEN + TAG_LEN; // bytes added to each record

// Current AAD-binding scheme version (see files.e2e_aad_version in src/db.js).
// A registration declares this explicitly - the server cannot infer it, since
// it never holds the E2E key or sees what encryptBytes actually did.
export const CURRENT_AAD_VERSION = 1;

// Builds the GCM additional-authenticated-data for one E2E record, binding it
// to a purpose ('name' for the encrypted-filename/metadata record, 'chunk' for
// a content record - stopping one being swapped in as the other), the file it
// belongs to, its position within that file, and its own plaintext length
// (stopping truncation/length-confusion splicing). `chunkIndex` is always 0
// for 'name' (there is only ever one). Deliberately omits shareId, for the
// same reason src/lib/filecrypt.js's aadV2 does: fileId (a 16-char randomId,
// not scoped per share) already prevents cross-file/cross-share splicing, and
// binding shareId would permanently break decryption for an E2E share renamed
// via PATCH /api/admin/shares/:id (the rename never touches blob contents).
// UTF-8 bytes with \0 separators are unambiguous because ids are restricted to
// [0-9A-Za-z_-] (same trick aadV2 uses).
export function recordAad(purpose, fileId, chunkIndex, plainLen) {
	return new TextEncoder().encode(`roeshare/e2e/v1\0${purpose}\0${fileId}\0${chunkIndex}\0${plainLen}`);
}

// ---- base64url ----
export function toB64u(bytes) {
	let s = '';
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64u(str) {
	const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
	const out = new Uint8Array(b.length);
	for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
	return out;
}

// ---- keys ----
export async function generateKey() {
	const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
	const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
	return { key, b64: toB64u(raw) };
}
export async function importKey(b64) {
	const raw = fromB64u(b64);
	if (raw.length !== 32) throw new Error('Invalid key');
	return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---- bytes ----
// Returns one record: IV || ciphertext+tag. `aad`, when given, is passed as
// GCM additionalData (see recordAad) - omitted (undefined) reproduces the
// exact legacy (aadVersion 0) ciphertext, byte for byte.
export async function encryptBytes(key, plain, aad) {
	const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
	const params = aad === undefined ? { name: 'AES-GCM', iv } : { name: 'AES-GCM', iv, additionalData: aad };
	const ct = new Uint8Array(await crypto.subtle.encrypt(params, key, plain));
	const out = new Uint8Array(IV_LEN + ct.length);
	out.set(iv, 0);
	out.set(ct, IV_LEN);
	return out;
}
// Decrypts one record produced by encryptBytes. `aad` must match whatever was
// passed to encryptBytes for this record (undefined for a legacy record).
export async function decryptBytes(key, record, aad) {
	const iv = record.subarray(0, IV_LEN);
	const ct = record.subarray(IV_LEN);
	const params = aad === undefined ? { name: 'AES-GCM', iv } : { name: 'AES-GCM', iv, additionalData: aad };
	return new Uint8Array(await crypto.subtle.decrypt(params, key, ct));
}

// ---- strings (file metadata) ----
export async function encryptString(key, str, aad) {
	return toB64u(await encryptBytes(key, new TextEncoder().encode(str), aad));
}
export async function decryptString(key, b64, aad) {
	return new TextDecoder().decode(await decryptBytes(key, fromB64u(b64), aad));
}

// Decrypt a whole stored blob that is a sequence of fixed-size records (each
// `recordSize` bytes except the last), where each plaintext chunk was `chunkSize`
// bytes. Returns the concatenated plaintext. `fileId`/`aadVersion` select the
// AAD scheme this file's records were sealed under (aadVersion 1 -> bound via
// recordAad per record; anything else -> legacy, no AAD).
export async function decryptFile(key, cipherBytes, chunkSize, fileId, aadVersion) {
	const recordSize = chunkSize + ENC_OVERHEAD;
	const parts = [];
	let total = 0;
	for (let pos = 0; pos < cipherBytes.length; pos += recordSize) {
		const rec = cipherBytes.subarray(pos, Math.min(pos + recordSize, cipherBytes.length));
		const chunkIndex = pos / recordSize;
		const plainLen = rec.length - ENC_OVERHEAD;
		const aad = aadVersion === 1 ? recordAad('chunk', fileId, chunkIndex, plainLen) : undefined;
		const plain = await decryptBytes(key, rec, aad);
		parts.push(plain);
		total += plain.length;
	}
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}
