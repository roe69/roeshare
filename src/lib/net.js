// IPv4/IPv6 address and CIDR parsing for the trusted-proxy allowlist
// (config.trustedProxyCidrs). No external dependency: this is a small,
// hand-rolled parser rather than a general-purpose IP library, scoped to
// exactly what clientIp()/requestScheme()/requestOrigin() need - parse an
// address, parse a CIDR, and test containment.

// Parse a plain IPv4 dotted-quad into 4 bytes, or null if not one.
function parseIPv4(str) {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(str);
	if (!m) return null;
	const bytes = new Uint8Array(4);
	for (let i = 0; i < 4; i++) {
		const n = Number(m[i + 1]);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		bytes[i] = n;
	}
	return bytes;
}

// Parse an IPv6 address (including "::" compression and an embedded IPv4
// tail like "::ffff:127.0.0.1") into 16 bytes, or null if not a valid one.
function parseIPv6(str) {
	// Strip a zone id (e.g. "fe80::1%eth0") - not meaningful for CIDR matching.
	const pct = str.indexOf('%');
	if (pct !== -1) str = str.slice(0, pct);
	if (!str) return null;

	// An embedded IPv4 tail is only valid as the last group; convert it to its
	// two equivalent hex groups so the rest of the parser is uniform.
	const lastColon = str.lastIndexOf(':');
	if (lastColon !== -1 && str.indexOf('.', lastColon) !== -1) {
		const v4 = parseIPv4(str.slice(lastColon + 1));
		if (!v4) return null;
		const g1 = ((v4[0] << 8) | v4[1]).toString(16);
		const g2 = ((v4[2] << 8) | v4[3]).toString(16);
		str = str.slice(0, lastColon + 1) + g1 + ':' + g2;
	}

	let headPart = str;
	let tailPart = '';
	let hasDouble = false;
	const dcIdx = str.indexOf('::');
	if (dcIdx !== -1) {
		if (str.indexOf('::', dcIdx + 1) !== -1) return null; // more than one "::"
		hasDouble = true;
		headPart = str.slice(0, dcIdx);
		tailPart = str.slice(dcIdx + 2);
	}

	const headGroups = headPart === '' ? [] : headPart.split(':');
	const tailGroups = tailPart === '' ? [] : tailPart.split(':');
	if (headGroups.some(g => g === '') || tailGroups.some(g => g === '')) return null;

	let allGroups;
	if (hasDouble) {
		const missing = 8 - headGroups.length - tailGroups.length;
		if (missing < 1) return null; // "::" must stand in for at least one group
		allGroups = [...headGroups, ...Array(missing).fill('0'), ...tailGroups];
	} else {
		if (headGroups.length !== 8) return null;
		allGroups = headGroups;
	}

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 8; i++) {
		const g = allGroups[i];
		if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
		const val = parseInt(g, 16);
		bytes[i * 2] = (val >> 8) & 0xff;
		bytes[i * 2 + 1] = val & 0xff;
	}
	return bytes;
}

// Parse any address string to { family: 4 | 6, bytes }. An IPv6 address that
// is really an IPv4-mapped address (::ffff:a.b.c.d, i.e. the first 10 bytes
// zero and the next 2 bytes 0xff) is normalized down to family 4 so it
// compares equal to the plain IPv4 form everywhere else in this module.
export function parseIp(str) {
	if (typeof str !== 'string') return null;
	let s = str.trim();
	if (!s) return null;
	// Strip surrounding brackets, e.g. "[::1]".
	if (s[0] === '[' && s.endsWith(']')) s = s.slice(1, -1);

	const v4 = parseIPv4(s);
	if (v4) return { family: 4, bytes: v4 };

	const v6 = parseIPv6(s);
	if (!v6) return null;
	let mapped = true;
	for (let i = 0; i < 10; i++) if (v6[i] !== 0) { mapped = false; break; }
	if (mapped && v6[10] === 0xff && v6[11] === 0xff) {
		return { family: 4, bytes: v6.slice(12, 16) };
	}
	return { family: 6, bytes: v6 };
}

// Parse "a.b.c.d/nn" or "xxxx::/nn" into { family, prefixLen, network } where
// `network` is the address bytes already masked to prefixLen. Returns null on
// anything malformed (bad address, missing/out-of-range prefix length).
export function parseCidr(str) {
	if (typeof str !== 'string') return null;
	const idx = str.indexOf('/');
	if (idx === -1) return null;
	const addrPart = str.slice(0, idx).trim();
	const lenPart = str.slice(idx + 1).trim();
	const ip = parseIp(addrPart);
	if (!ip) return null;
	if (!/^\d{1,3}$/.test(lenPart)) return null;
	const prefixLen = Number(lenPart);
	const maxLen = ip.family === 4 ? 32 : 128;
	if (prefixLen < 0 || prefixLen > maxLen) return null;
	return { family: ip.family, prefixLen, network: maskBytes(ip.bytes, prefixLen) };
}

// Zero out every bit beyond prefixLen, returning a new masked byte array.
function maskBytes(bytes, prefixLen) {
	const out = new Uint8Array(bytes.length);
	let remaining = prefixLen;
	for (let i = 0; i < bytes.length; i++) {
		if (remaining >= 8) {
			out[i] = bytes[i];
			remaining -= 8;
		} else if (remaining > 0) {
			const mask = 0xff << (8 - remaining) & 0xff;
			out[i] = bytes[i] & mask;
			remaining = 0;
		} else {
			out[i] = 0;
		}
	}
	return out;
}

// Whether the given address string falls inside any of the parsed CIDRs
// (as returned by parseCidr - callers parse the configured list once at boot
// and pass the parsed array in on every request).
export function ipInCidrs(ipStr, cidrs) {
	const ip = parseIp(ipStr);
	if (!ip) return false;
	for (const cidr of cidrs) {
		if (cidr.family !== ip.family) continue;
		const masked = maskBytes(ip.bytes, cidr.prefixLen);
		if (masked.length === cidr.network.length && masked.every((b, i) => b === cidr.network[i])) return true;
	}
	return false;
}

// Parse a comma-separated CIDR list. Invalid entries are dropped and reported
// via onInvalid(entry) rather than throwing, so one typo in an env var can't
// crash boot - it just doesn't get trusted.
export function parseCidrList(raw, onInvalid) {
	const out = [];
	for (const part of String(raw || '').split(',')) {
		const s = part.trim();
		if (!s) continue;
		const cidr = parseCidr(s);
		if (cidr) out.push(cidr);
		else if (onInvalid) onInvalid(s);
	}
	return out;
}
