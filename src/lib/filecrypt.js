// Encryption at rest. Blobs are stored as AES-256-CTR ciphertext; plaintext only
// ever exists in memory while streaming to an authorized request. CTR is used
// (not GCM) because it is seekable: any byte range can be decrypted on its own,
// which preserves HTTP range requests / video seeking and resumable uploads.
//
// Key: derived once from config.secret via scrypt. Per-file random 16-byte IV is
// stored alongside the file row. Losing SECRET makes existing files unreadable,
// so SECRET must be backed up. CTR provides confidentiality, not integrity - the
// app's access control and the unguessable ids are the authorization boundary.

import { createCipheriv, createDecipheriv, scryptSync, randomBytes } from 'node:crypto';
import { config } from '../config.js';

export const ENC_ENABLED = true;

// 32-byte key from the high-entropy secret. Deterministic for a given SECRET.
const KEY = scryptSync(config.secret, 'roeshare-fs-key-v1', 32);

export function newIv() {
	return randomBytes(16).toString('hex');
}

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
