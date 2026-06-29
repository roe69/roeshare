// End-to-end encryption helpers (WebCrypto, AES-256-GCM). The key is generated
// in the browser, never sent to the server, and shared only via the URL fragment
// (#key), which browsers never transmit. Files are encrypted per record (one per
// upload chunk): each record is [12-byte random IV][ciphertext+16-byte GCM tag],
// so the server only ever stores ciphertext and tampering is detected on decrypt.

export const IV_LEN = 12;
export const TAG_LEN = 16;
export const ENC_OVERHEAD = IV_LEN + TAG_LEN; // bytes added to each record

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
// Returns one record: IV || ciphertext+tag.
export async function encryptBytes(key, plain) {
	const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
	const out = new Uint8Array(IV_LEN + ct.length);
	out.set(iv, 0);
	out.set(ct, IV_LEN);
	return out;
}
// Decrypts one record produced by encryptBytes.
export async function decryptBytes(key, record) {
	const iv = record.subarray(0, IV_LEN);
	const ct = record.subarray(IV_LEN);
	return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

// ---- strings (file metadata) ----
export async function encryptString(key, str) {
	return toB64u(await encryptBytes(key, new TextEncoder().encode(str)));
}
export async function decryptString(key, b64) {
	return new TextDecoder().decode(await decryptBytes(key, fromB64u(b64)));
}

// Decrypt a whole stored blob that is a sequence of fixed-size records (each
// `recordSize` bytes except the last), where each plaintext chunk was `chunkSize`
// bytes. Returns the concatenated plaintext.
export async function decryptFile(key, cipherBytes, chunkSize) {
	const recordSize = chunkSize + ENC_OVERHEAD;
	const parts = [];
	let total = 0;
	for (let pos = 0; pos < cipherBytes.length; pos += recordSize) {
		const rec = cipherBytes.subarray(pos, Math.min(pos + recordSize, cipherBytes.length));
		const plain = await decryptBytes(key, rec);
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
