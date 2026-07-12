// Shared filename sanitization (was duplicated in routes/uploads.js and
// routes/api.js - M-1). Keeps a SAFE relative path so dragged folders preserve
// their structure (used as the display name, the Content-Disposition response
// header, and the zip entry path). Drops any "." / ".." / empty / drive
// segments and control chars, so it can never traverse - and it is never used
// as an on-disk path anyway (blobs are stored under the generated file id).
//
// M-1: also strips Unicode bidi-control characters (U+202A-U+202E, the
// legacy LRE/RLE/PDF/LRO/RLO embed/override pair, and U+2066-U+2069, the
// modern LRI/RLI/FSI/PDI isolates) and zero-width characters (U+200B-U+200F,
// the ZWSP/ZWNJ/ZWJ/LRM/RLM block, plus U+FEFF the BOM/ZWNBSP).
//
// Left in place, an RTLO-style character (e.g. U+202E) lets an uploaded name
// like "invoice_<RTLO>txt.exe" DISPLAY reversed as "invoice_exe.txt" - on the
// share page, in the downloaded file's suggested name (contentDisposition in
// lib/http.js encodes whatever sanitizeName returns), and in zip entry names
// - while the actual extension stays .exe. None of these characters are ever
// legitimate in a filename, so they are stripped outright rather than escaped.
const CONTROL_RE = /[\x00-\x1f\x7f]/g;
const BIDI_AND_ZERO_WIDTH_RE = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

export function sanitizeName(name) {
	const parts = String(name ?? '')
		.split(/[/\\]+/)
		.map(s => s.replace(CONTROL_RE, '').replace(BIDI_AND_ZERO_WIDTH_RE, '').replace(/^[A-Za-z]:$/, '').trim())
		.filter(s => s && s !== '.' && s !== '..');
	return parts.join('/').slice(0, 1024) || 'file';
}
