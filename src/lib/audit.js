// Minimal structured audit-event logger. There is no dedicated sink yet (see
// lib/keys.js's auditIntegrityKey, reserved for a future HMAC-chained audit
// log) - this is deliberately just a single structured console.log line, so
// every call site already emits the right event name/shape and a real sink
// can be wired in later without touching any caller.
export function audit(event, data = {}) {
	console.log(`[audit] ${event} ${JSON.stringify(data)}`);
}
