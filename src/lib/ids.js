// URL-safe random identifiers. Uses a crypto RNG and a base58-ish alphabet that
// avoids easily-confused characters (0/O, 1/l/I). IDs are opaque, unguessable,
// and safe to drop straight into a URL path segment.

import { randomBytes } from 'node:crypto';

const ALPHABET = '23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';

export function randomId(length = 12) {
	// Rejection sampling against the alphabet length keeps the distribution flat.
	const out = new Array(length);
	const bytes = randomBytes(length * 2);
	let bi = 0;
	for (let i = 0; i < length; i++) {
		let b;
		do {
			if (bi >= bytes.length) {
				// Extremely unlikely top-up.
				const more = randomBytes(length);
				for (let j = 0; j < more.length; j++) bytes[bi % bytes.length] = more[j];
				bi = 0;
			}
			b = bytes[bi++];
		} while (b >= 256 - (256 % ALPHABET.length));
		out[i] = ALPHABET[b % ALPHABET.length];
	}
	return out.join('');
}

// Share IDs are short and human-shareable; file IDs and tokens are longer.
export const newShareId = () => randomId(10);
export const newFileId = () => randomId(16);
export const newToken = () => randomId(32);
