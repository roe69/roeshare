// HTML-attribute escaping for the one place this codebase templates
// user-controlled text (a share title, a filename) directly into server-
// rendered HTML (see routes/pages.js's embed meta tags). Every dynamic value
// MUST pass through this before landing inside an attribute value - skipping
// it anywhere is a textbook attribute-breakout XSS vector (a title of
// `"><script>...` closing the attribute and the tag).

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

// Escape a value for safe use inside a double-quoted HTML attribute, and
// strip C0 control characters (0x00-0x1F minus tab/LF/CR, and 0x7F) - they
// have no legitimate place in an attribute value and some can confuse
// downstream HTML parsers or crawlers. `null`/`undefined` become ''.
export function escapeHtmlAttr(value) {
	const s = value == null ? '' : String(value);
	// eslint-disable-next-line no-control-regex
	const stripped = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
	return stripped.replace(/[&<>"']/g, ch => ESCAPES[ch]);
}
