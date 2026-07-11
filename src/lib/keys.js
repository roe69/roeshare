// Central key derivation (F-18: one root secret was previously reused, raw,
// for HMAC signing, credential tagging, AND at-rest encryption - a compromise
// or rotation of SECRET affected all of them at once with no way to separate
// blast radius). Every cryptographic subsystem below pulls its key from here
// instead of touching config.secret directly, so each purpose gets its own
// independent, domain-separated subkey (HKDF-SHA256, labeled per RFC 5869).
//
// Rotating SECRET is still a single global event - every subkey below changes
// at once - but the separation means a future SECRET rotation strategy (e.g.
// keeping an old at-rest key registered under its own id while new files use
// a new one) is possible without redesigning the format; see AT_REST_KEYS.
//
// DEPLOY NOTE: the first boot after this module ships derives tokenSigningKey
// and credentialTagKey from config.secret instead of using it directly, which
// is a DIFFERENT value than before - every outstanding signed token (admin
// session, upload-password session, per-share access token, API-key portal
// session, quick-access link) stops verifying at once. This is an expected,
// one-time forced re-login, not a bug. Edit tokens and API keys are stored as
// plain SHA-256 hashes (not HMAC'd) and are unaffected; E2E client-side
// crypto never touches this module; existing at-rest v1 blobs keep using
// their own separately-derived scrypt key (see filecrypt.js) and are also
// unaffected.

import { hkdfSync } from 'node:crypto';
import { config } from '../config.js';

const IKM = Buffer.from(config.secret, 'utf8');
const SALT = Buffer.from('roeshare-hkdf-salt-v1', 'utf8');

// hkdfSync returns an ArrayBuffer (not a Buffer) per the Node/Bun API - wrap
// it before use as an HMAC or cipher key.
const derive = label => Buffer.from(hkdfSync('sha256', IKM, SALT, Buffer.from(label, 'utf8'), 32));

export const tokenSigningKey = derive('roeshare/token-signing/v1');
export const credentialTagKey = derive('roeshare/credential-tag/v1');
// Derived and exported now, deliberately unused, to freeze the label for a
// future audit-log HMAC-chaining feature.
export const auditIntegrityKey = derive('roeshare/audit-integrity/v1');

// At-rest encryption wrapping keys, keyed by a small integer id. This id (not
// the key material) is what gets embedded in every v2 chunk record and in
// files.key_id, so a file always records which entry of this map its
// per-file key was derived from (see filecrypt.js's fileKeyForV2, which HKDFs
// the actual per-file key from one of these plus the file's own random
// salt). A future SECRET rotation would add a new entry here (derived from
// the new SECRET, under a new id) and bump CURRENT_AT_REST_KEY_ID for new
// writes, while old files keep decrypting because their stored key_id still
// resolves to the old entry - none of that is implemented yet, only the slot
// exists.
export const AT_REST_KEYS = new Map([[1, derive('roeshare/at-rest-wrap/v1')]]);
export const CURRENT_AT_REST_KEY_ID = 1;
