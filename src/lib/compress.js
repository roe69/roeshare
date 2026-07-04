// Response compression (brotli preferred, gzip fallback). Applied to text-like
// responses only; file downloads/previews/zips are skipped because they set
// Content-Disposition / Accept-Ranges / a non-text type, so range streaming and
// already-compressed media are never buffered or re-compressed.

import { gzipSync, brotliCompressSync, constants } from 'node:zlib';

const COMPRESSIBLE = /^(text\/|application\/(json|manifest\+json|javascript|xml)|image\/svg)/i;

// Don't bother compressing tiny payloads - the framing overhead isn't worth it.
const MIN_BYTES = 256;

// Don't run a huge body through the blocking sync brotli/gzip call - that would
// stall the event loop for every other in-flight request. Bodies above this size
// are served uncompressed instead (they are expected to be rare for the
// text/JSON responses this module handles at all).
const MAX_BYTES = 2 * 1024 * 1024;

export function pickEncoding(req) {
	const ae = req.headers.get('accept-encoding') || '';
	if (/\bbr\b/.test(ae)) return 'br';
	if (/\bgzip\b/.test(ae)) return 'gzip';
	return null;
}

export function compressBytes(buf, encoding, quality = 5) {
	if (encoding === 'br') {
		return brotliCompressSync(buf, {
			params: { [constants.BROTLI_PARAM_QUALITY]: quality, [constants.BROTLI_PARAM_SIZE_HINT]: buf.length },
		});
	}
	if (encoding === 'gzip') return gzipSync(buf, { level: quality >= 9 ? 9 : 6 });
	return buf;
}

export function isCompressibleType(type) {
	return COMPRESSIBLE.test(type || '');
}

// Whether a finished Response is safe to compress: a 200 with a text-like body
// that is not a file stream (no Content-Disposition / range headers) and not
// already encoded.
function shouldCompress(res) {
	if (res.status !== 200) return false;
	const h = res.headers;
	if (h.get('content-encoding')) return false;
	if (h.get('content-disposition') || h.get('content-range') || h.get('accept-ranges')) return false;
	return isCompressibleType(h.get('content-type'));
}

// Compress a dynamic response on the fly. Buffers the (small, text) body, so it
// is only ever called for responses that pass shouldCompress().
export async function compressResponse(req, res) {
	if (!shouldCompress(res)) return res;
	const enc = pickEncoding(req);
	if (!enc) return res;
	const buf = Buffer.from(await res.arrayBuffer());
	const headers = new Headers(res.headers);
	headers.set('Vary', 'Accept-Encoding');
	if (buf.length < MIN_BYTES) return new Response(buf, { status: res.status, headers });
	if (buf.length > MAX_BYTES) return new Response(buf, { status: res.status, headers });
	const out = compressBytes(buf, enc);
	headers.set('Content-Encoding', enc);
	headers.set('Content-Length', String(out.length));
	return new Response(out, { status: res.status, headers });
}
