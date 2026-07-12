// At-rest encryption for server-managed (non-E2E) blobs. Two on-disk formats
// coexist, disambiguated by files.enc_version (never by content sniffing):
//
//   v1 - AES-256-CTR (this file's original format). Seekable but has NO
//        authentication: ciphertext is malleable, so silent corruption or
//        tampering on disk is undetectable (see F-03 in the security audit).
//        Every v1 blob is automatically, transparently re-encrypted to v2 in
//        the background (see lib/migrate.js, M-06) - this format is never
//        written for a new file, and a v1 row is a temporary state, not a
//        permanent one. The decrypt path here stays forever regardless (a
//        migration can fail-safe and leave a file on v1 indefinitely - see
//        migrate.js's verify step).
//   v2 - AES-256-GCM, sealed independently in fixed-size plaintext chunks
//        (PLAIN_CHUNK bytes each; see the ON-DISK RECORD layout below). Every
//        chunk is authenticated on its own, so a Range read only ever has to
//        decrypt the chunk(s) it actually needs, and any tampering/corruption
//        is detected BEFORE the affected plaintext is released to a caller.
//        Used for every new file.
//
// v1 key: derived once from config.secret via scrypt, exactly as before
// (unrelated to the HKDF subkeys in lib/keys.js - the v1 format predates that
// separation and is left alone). Still needed by lib/migrate.js to decrypt a
// v1 blob's plaintext one final time on its way to v2.
//
// v2 keys: see lib/keys.js's AT_REST_KEYS (the wrapping key, chosen by
// files.key_id) and fileKeyForV2 below (the actual per-file key, HKDF-derived
// from a wrapping key plus a random 16-byte per-file salt stored in
// files.iv). Losing SECRET makes every at-rest file unreadable in both
// formats, so SECRET must be backed up.
//
// ON-DISK RECORD (v2), one per PLAIN_CHUNK-sized slice of plaintext, laid out
// contiguously in the blob file:
//
//   [version u8 = 0x02][keyId u8][nonce 12 bytes][ciphertext plainLen bytes][gcmTag 16 bytes]
//
// RECORD_OVERHEAD (everything except the ciphertext) is 30 bytes; a full
// record is FULL_RECORD = PLAIN_CHUNK + 30 bytes. Every record except a
// file's last is exactly FULL_RECORD; the last record's plaintext length is
// size % PLAIN_CHUNK (or PLAIN_CHUNK if size is an exact multiple; a 0-byte
// file has zero records). The chunk-splitting/disk-offset bookkeeping lives
// in storage.js (writeChunk/blobRangeStream) - this module only seals/opens
// one record at a time.
//
// NONCE: 12 random bytes, freshly generated at EVERY seal of a record
// (including a reseal of the tail record with different/extended plaintext
// under the same chunkIndex - see storage.js's writeChunk for when that
// happens). Do NOT "simplify" this to a per-file base nonce plus a
// chunk-index counter: the upload protocol legitimately reseals a record
// (retried PATCH after a partial write; a non-chunk-aligned PATCH boundary),
// which would reuse a counter-derived nonce for two different plaintexts
// under the same key - a catastrophic AES-GCM failure (keystream and
// auth-key recovery). Random-per-seal nonces make every seal independent;
// collision safety only needs to hold per key, and the key is per-file (see
// fileKeyForV2), so even a 1 TiB file (~4.2M seals) has collision
// probability far below 2^-50.
//
// AAD binds keyId, fileId, chunkIndex, and the record's own plaintext length
// - but deliberately NOT shareId (an admin slug rename changes a share's id
// without touching blob contents) or the total file length (unknown at
// streaming-write time; whole-file truncation is instead caught structurally
// by the read path failing to parse the DB-authoritative expected record
// layout). fileId alone already prevents cross-file/cross-share splicing,
// and the per-file key independently binds fileId again.

import { createCipheriv, createDecipheriv, hkdfSync, scryptSync, randomBytes } from 'node:crypto';
import { config } from '../config.js';
import { AT_REST_KEYS } from './keys.js';

export const ENC_ENABLED = true;

// ---- v1 (AES-256-CTR, unauthenticated) - unchanged, kept only for legacy reads ----

// 32-byte key from the high-entropy secret. Deterministic for a given SECRET.
const KEY = scryptSync(config.secret, 'roeshare-fs-key-v1', 32);

// Add an integer block count to a big-endian 128-bit counter (the IV), matching
// how AES-CTR advances the counter one block (16 bytes) at a time.
function counterAt(ivHex, byteOffset) {
	const c = Buffer.from(ivHex, 'hex'); // 16 bytes, mutated copy
	let carry = Math.floor(byteOffset / 16);
	for (let i = 15; i >= 0 && carry > 0; i--) {
		carry += c[i];
		c[i] = carry & 0xff;
		carry = Math.floor(carry / 256);
	}
	return { counterIV: c, skip: byteOffset % 16 };
}

// Encrypt (or decrypt - CTR is symmetric) a buffer that begins at `byteOffset`
// within the logical file. Returns a buffer of the same length.
export function transformAt(ivHex, byteOffset, data) {
	const { counterIV, skip } = counterAt(ivHex, byteOffset);
	const cipher = createCipheriv('aes-256-ctr', KEY, counterIV);
	if (skip) cipher.update(Buffer.alloc(skip)); // align keystream to the offset
	return cipher.update(Buffer.from(data));
}

// Wrap a ciphertext ReadableStream (already sliced to start at `startByte`) in a
// stream that yields decrypted plaintext.
export function decryptStream(ivHex, startByte, source) {
	const { counterIV, skip } = counterAt(ivHex, startByte);
	const decipher = createDecipheriv('aes-256-ctr', KEY, counterIV);
	if (skip) decipher.update(Buffer.alloc(skip));
	const reader = source.getReader();
	return new ReadableStream({
		async pull(controller) {
			try {
				const { done, value } = await reader.read();
				if (done) {
					const fin = decipher.final();
					if (fin.length) controller.enqueue(new Uint8Array(fin));
					controller.close();
					return;
				}
				const out = decipher.update(Buffer.from(value));
				if (out.length) controller.enqueue(new Uint8Array(out));
			} catch (e) {
				controller.error(e);
			}
		},
		cancel(reason) {
			reader.cancel(reason);
		},
	});
}

// ---- v2 (AES-256-GCM, per-chunk authenticated) -----------------------------

export const PLAIN_CHUNK = 262144; // 256 KiB
export const RECORD_OVERHEAD = 30; // version(1) + keyId(1) + nonce(12) + gcmTag(16)
export const FULL_RECORD = PLAIN_CHUNK + RECORD_OVERHEAD;

// A fresh random 16-byte value, hex-encoded. Used as the v2 per-file HKDF
// salt (stored in files.iv - the column's meaning is disambiguated by
// files.enc_version, never by content) and, before v2, as the v1 CTR IV; the
// two formats happen to want the same shape, so one helper covers both.
export function newFileSalt() {
	return randomBytes(16).toString('hex');
}

// Per-file v2 key: HKDF-SHA256 over the wrapping key named by `keyId` (see
// lib/keys.js's AT_REST_KEYS), salted with the file's own random 16-byte
// salt, info-bound to the file id. Every record of a file is encrypted under
// this one key, so nonce collision safety only has to hold within one file
// (see the module comment).
export function fileKeyForV2(fileId, fileSaltHex, keyId) {
	const master = AT_REST_KEYS.get(keyId);
	if (!master) throw new Error(`unknown at-rest key id ${keyId} - was SECRET rotated without registering the old key?`);
	const salt = Buffer.from(fileSaltHex, 'hex');
	const info = Buffer.from(`roeshare/file-key/v2\0${fileId}`, 'utf8');
	return Buffer.from(hkdfSync('sha256', master, salt, info, 32));
}

function aadV2(keyId, fileId, chunkIndex, plainLen) {
	// ids match /^[0-9A-Za-z_-]+$/ (storage.js), so \0 is an unambiguous separator.
	return Buffer.from(`roeshare/v2\0${keyId}\0${fileId}\0${chunkIndex}\0${plainLen}`, 'utf8');
}

// Seal one plaintext chunk (at most PLAIN_CHUNK bytes) into a v2 record. A
// fresh random nonce is minted on every call - see the module comment on why
// that is mandatory, not an implementation detail.
export function sealRecordV2(fileKey, keyId, fileId, chunkIndex, plaintext) {
	const nonce = randomBytes(12);
	const cipher = createCipheriv('aes-256-gcm', fileKey, nonce);
	cipher.setAAD(aadV2(keyId, fileId, chunkIndex, plaintext.length));
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([Buffer.from([2, keyId & 0xff]), nonce, ciphertext, tag]);
}

// Open (decrypt + authenticate) one v2 record. Throws - BEFORE returning any
// plaintext - if the record is too short to be well-formed, carries an
// unexpected version/keyId, or fails GCM tag verification (tamper/corruption,
// or a chunkIndex/fileId/keyId that doesn't match what it was sealed under).
// Callers must never release partial output from a call that threw.
export function openRecordV2(fileKey, keyId, fileId, chunkIndex, record) {
	const buf = record instanceof Buffer ? record : Buffer.from(record);
	if (buf.length <= RECORD_OVERHEAD) throw new Error('at-rest record too short (truncated or corrupt)');
	const version = buf[0];
	if (version !== 2) throw new Error(`unsupported at-rest record version ${version}`);
	const recordKeyId = buf[1];
	if (recordKeyId !== keyId) throw new Error('at-rest record key id does not match the file row');
	const nonce = buf.subarray(2, 14);
	const tag = buf.subarray(buf.length - 16);
	const ciphertext = buf.subarray(14, buf.length - 16);
	const decipher = createDecipheriv('aes-256-gcm', fileKey, nonce);
	decipher.setAAD(aadV2(keyId, fileId, chunkIndex, ciphertext.length));
	decipher.setAuthTag(tag);
	// final() throws on authentication failure - this is the tamper/corruption
	// signal, and it fires before update()'s output would otherwise be trusted.
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
