// Upload page: drag-and-drop, resumable chunked uploads, share options, result
// card with link, copy, and QR. Uses shared helpers and the rl-* design system.

import { el, $, api, ApiError, toast, toastOk, toastErr, copyText, formatBytes, fileGlyph } from '/js/shared.js';
import { generateKey, encryptBytes, encryptString, ENC_OVERHEAD } from '/js/e2e.js';
import { mountSidebar } from '/js/sidebar.js';

// The shared rail. The quick-access upload link is an admin-only control (it
// lives in the admin Server settings, by the upload password it depends on), so
// the upload page does not surface it.
mountSidebar({ active: 'upload' });

const EDIT_KEY = id => `roeshare:edit:${id}`;
const MAX_CHUNK_RETRIES = 3;
// Consecutive non-409 chunk failures at the same offset before giving up outright
// (rather than relying solely on the large maxGuard to eventually bail out).
const MAX_OFFSET_FAILURES = 5;
const SLUG_RE = /^[A-Za-z0-9_-]{3,64}$/;
const SLUG_BAD_CHARS = /[^A-Za-z0-9_-]/g;

// Exponential backoff with jitter between chunk-retry attempts, so a persistent
// server/network error does not hammer the server back-to-back on a large upload.
const sleep = ms => new Promise(r => setTimeout(r, ms));
const backoff = n => Math.min(15000, 500 * 2 ** n) + Math.random() * 250;

let config = null;
// Captured from config on load so resetForm() can restore the checkbox to the
// server's default even though config may be refreshed again by then.
let defaultE2e = false;
const selected = []; // { file, key, row: { wrap, bar, status }, done }
let uploading = false;
let keyCounter = 0;
let overallBar = null;
let overallStat = null;

// Overall transfer-rate tracking (smoothed bytes/sec) for the speed + ETA line.
const SPEED_ALPHA = 0.3;
let speedStartTs = 0;
let speedLastTs = 0;
let speedLastBytes = 0;
let speedBps = 0;

// ---- Elements --------------------------------------------------------------
const dropzone = $('#dropzone');
const fileInput = $('#file-input');
const fileListEl = $('#file-list');
const uploadBtn = $('#upload-btn');
const resultEl = $('#result');
// ---- Config ----------------------------------------------------------------
// The upload portal is only served once authorized (the server gates the page
// and this script behind the upload-password cookie), so there is no client gate
// here - just load config for chunk size and limits.
async function loadConfig() {
	try {
		config = await api.get('/api/config');
		defaultE2e = !!config.defaultE2e;
		$('#opt-e2e').checked = defaultE2e;
	} catch (e) {
		toastErr('Could not load server config');
	}
}

// ---- File selection --------------------------------------------------------
// Accepts File objects or { file, path } entries (drag-with-folders). The path
// is the relative path within a dropped folder, preserved for display + upload.
function addFiles(list) {
	if (uploading) return;
	let added = 0;
	for (const entry of list) {
		if (!entry) continue;
		const file = entry.file || entry;
		if (!file || !file.name) continue;
		const path = entry.path || file.webkitRelativePath || file.name;
		selected.push({ file, path, key: ++keyCounter, row: null, done: false });
		added++;
	}
	if (added) renderFileList();
}

function removeFile(key) {
	if (uploading) return;
	const i = selected.findIndex(s => s.key === key);
	if (i >= 0) selected.splice(i, 1);
	renderFileList();
}

function clearAll() {
	if (uploading) return;
	selected.length = 0;
	renderFileList();
}

function resetSpeed() {
	speedStartTs = 0;
	speedLastTs = 0;
	speedLastBytes = 0;
	speedBps = 0;
}

// Human-friendly remaining time. "finishing..." covers near-zero / unknown.
function formatEta(seconds) {
	if (!Number.isFinite(seconds) || seconds < 1) return 'finishing...';
	if (seconds < 60) return `about ${Math.round(seconds)}s left`;
	if (seconds < 3600) return `about ${Math.round(seconds / 60)}m left`;
	return `about ${Math.round(seconds / 3600)}h left`;
}

// Sample cumulative bytes into a smoothed rate, then render speed + ETA.
function updateSpeed(done, total) {
	if (!overallStat) return;
	const now = Date.now();
	if (!speedStartTs) {
		speedStartTs = now;
		speedLastTs = now;
		speedLastBytes = done;
		return;
	}
	const dt = (now - speedLastTs) / 1000;
	// Gate on a small interval so rapid tiny chunks do not make the rate jumpy.
	if (dt >= 0.25) {
		const inst = Math.max(0, done - speedLastBytes) / dt;
		speedBps = speedBps > 0 ? SPEED_ALPHA * inst + (1 - SPEED_ALPHA) * speedBps : inst;
		speedLastTs = now;
		speedLastBytes = done;
	}
	if (speedBps > 0) {
		const eta = Math.max(0, total - done) / speedBps;
		overallStat.textContent = `${formatBytes(speedBps)}/s - ${formatEta(eta)}`;
	}
}

function updateOverall() {
	if (!overallBar) return;
	let done = 0;
	let total = 0;
	for (const it of selected) {
		total += it.file.size;
		done += it.done ? it.file.size : it._received || 0;
	}
	overallBar.style.width = (total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 100) + '%';
	updateSpeed(done, total);
}

function renderFileList() {
	fileListEl.textContent = '';
	if (!selected.length) {
		fileListEl.classList.add('rl-hidden');
		refreshUploadBtn();
		return;
	}
	fileListEl.classList.remove('rl-hidden');
	refreshUploadBtn();

	let total = 0;
	for (const item of selected) total += item.file.size;

	// Header: count + total size, with Clear all (idle) or an overall bar (uploading).
	fileListEl.append(
		el('div', { class: 'rl-row', style: 'justify-content:space-between;align-items:center' },
			el('div', { class: 'rl-label' }, `${selected.length} file${selected.length === 1 ? '' : 's'} · ${formatBytes(total)}`),
			uploading ? (overallStat = el('span', { class: 'rl-help' })) : el('button', { class: 'rl-btn rl-btn-ghost rl-btn-sm', onClick: clearAll }, 'Clear all'),
		),
	);
	if (uploading) {
		overallBar = el('div', { class: 'rl-progress-bar' });
		fileListEl.append(el('div', { class: 'rl-progress', style: 'margin-bottom:var(--rl-space-1)' }, overallBar));
	} else {
		overallBar = null;
		overallStat = null;
	}

	// Compact, scrollable list of rows.
	const rows = el('div', { class: 'rl-filerows' });
	for (const item of selected) {
		const bar = el('div', { class: 'rl-progress-bar' });
		const status = el('span', { class: 'rl-filerow-size' }, formatBytes(item.file.size));

		// Show the relative path with the folder part dimmed and the filename bold.
		const name = el('div', { class: 'rl-filerow-name rl-truncate', title: item.path });
		const slash = item.path.lastIndexOf('/');
		if (slash >= 0) name.append(el('span', { class: 'rl-filerow-dir' }, item.path.slice(0, slash + 1)));
		name.append(el('span', { class: 'rl-filerow-base' }, slash >= 0 ? item.path.slice(slash + 1) : item.path));

		const row = el(
			'div',
			{ class: 'rl-filerow' },
			el('div', { class: 'rl-filerow-icon', 'aria-hidden': 'true' }, fileGlyph(item.file.type, item.file.name)),
			name,
			status,
			uploading
				? null
				: el('button', { class: 'rl-filerow-x', 'aria-label': 'Remove', title: 'Remove', onClick: () => removeFile(item.key) }, '✕'),
		);
		if (uploading) row.append(el('div', { class: 'rl-filerow-progress' }, bar));
		item.row = { bar, status };
		if (item.done) {
			bar.style.width = '100%';
			status.textContent = 'Done';
		}
		rows.append(row);
	}
	fileListEl.append(rows);
	updateOverall();
}

function setProgress(item, received, size) {
	item._received = received;
	updateOverall();
	if (!item.row) return;
	const pct = size > 0 ? Math.min(100, Math.round((received / size) * 100)) : 100;
	item.row.bar.style.width = pct + '%';
	item.row.status.textContent = item.done ? 'Done' : `${pct}%`;
}

// ---- Drag and drop ---------------------------------------------------------
function walkEntry(entry, out, prefix) {
	return new Promise(resolve => {
		if (entry.isFile) {
			entry.file(
				f => {
					out.push({ file: f, path: prefix + f.name });
					resolve();
				},
				() => resolve(),
			);
		} else if (entry.isDirectory) {
			const dirPrefix = prefix + entry.name + '/';
			const reader = entry.createReader();
			const readBatch = () =>
				reader.readEntries(
					async ents => {
						if (!ents.length) return resolve();
						for (const en of ents) await walkEntry(en, out, dirPrefix);
						readBatch();
					},
					() => resolve(),
				);
			readBatch();
		} else resolve();
	});
}

async function filesFromDrop(dt) {
	const items = dt.items;
	if (items && items.length && items[0].webkitGetAsEntry) {
		const entries = [];
		for (const it of items) {
			const e = it.webkitGetAsEntry && it.webkitGetAsEntry();
			if (e) entries.push(e);
		}
		if (entries.length) {
			const out = [];
			for (const e of entries) await walkEntry(e, out, '');
			return out;
		}
	}
	return [...dt.files];
}

dropzone.addEventListener('click', () => !uploading && fileInput.click());
dropzone.addEventListener('keydown', e => {
	if ((e.key === 'Enter' || e.key === ' ') && !uploading) {
		e.preventDefault();
		fileInput.click();
	}
});
$('#pick-files').addEventListener('click', e => {
	e.stopPropagation();
	if (!uploading) fileInput.click();
});
fileInput.addEventListener('change', () => {
	addFiles(fileInput.files);
	fileInput.value = '';
});

['dragenter', 'dragover'].forEach(ev =>
	dropzone.addEventListener(ev, e => {
		e.preventDefault();
		if (!uploading) dropzone.classList.add('is-dragover');
	}),
);
['dragleave', 'dragend'].forEach(ev =>
	dropzone.addEventListener(ev, e => {
		e.preventDefault();
		dropzone.classList.remove('is-dragover');
	}),
);
dropzone.addEventListener('drop', async e => {
	e.preventDefault();
	dropzone.classList.remove('is-dragover');
	if (uploading) return;
	const files = await filesFromDrop(e.dataTransfer);
	addFiles(files);
});

// Paste files/images from the clipboard anywhere on the page.
document.addEventListener('paste', e => {
	if (uploading) return;
	const items = e.clipboardData && e.clipboardData.items;
	if (!items) return;
	const out = [];
	for (const it of items) {
		if (it.kind !== 'file') continue;
		const f = it.getAsFile();
		if (!f) continue;
		if (f.name) out.push(f);
		else {
			// Pasted screenshots have no filename - synthesize one from the mime type.
			const ext = (f.type.split('/')[1] || 'bin').split('+')[0];
			out.push(new File([f], `pasted-${Math.floor(Date.now() / 1000)}.${ext}`, { type: f.type }));
		}
	}
	if (out.length) {
		e.preventDefault();
		addFiles(out);
		toastOk(`Added ${out.length} pasted file${out.length === 1 ? '' : 's'}`);
	}
});

// ---- Upload flow -----------------------------------------------------------
function readOptions() {
	const title = $('#opt-title').value.trim();
	const slug = $('#opt-slug').value.trim();
	const password = $('#opt-password').value;
	const passwordConfirm = $('#opt-password-confirm').value;

	if (slug && !SLUG_RE.test(slug)) {
		throw new Error('Custom link must be 3-64 characters: letters, numbers, hyphens or underscores');
	}
	if (password && password !== passwordConfirm) {
		throw new Error('Passwords do not match');
	}

	// Expiry: a preset number of seconds, 0 = never, or a custom future date.
	let expiresIn;
	const expSel = $('#opt-expiry').value;
	if (expSel === 'custom') {
		const v = $('#opt-expiry-custom').value;
		if (!v) throw new Error('Pick a custom expiry date');
		const ms = new Date(v).getTime();
		if (!Number.isFinite(ms)) throw new Error('That expiry date is not valid');
		const secs = Math.round((ms - Date.now()) / 1000);
		if (secs <= 0) throw new Error('The expiry date must be in the future');
		expiresIn = secs;
	} else {
		expiresIn = Number(expSel);
	}

	const body = { expiresIn };

	// Download limit replaces the old max-downloads + one-time pair.
	const limSel = $('#opt-limit').value;
	if (limSel === 'onetime') {
		body.oneTime = true;
	} else if (limSel === 'custom') {
		const n = parseInt($('#opt-limit-num').value, 10);
		if (!Number.isFinite(n) || n < 1) throw new Error('Enter a download limit of 1 or more');
		body.maxDownloads = n;
	}

	if (title) body.title = title;
	if (slug) body.slug = slug;
	if (password) body.password = password;
	if ($('#opt-e2e').checked) body.e2e = true;
	return body;
}

// Minimum value for the custom datetime-local picker: one minute from now,
// formatted as the browser's local "YYYY-MM-DDTHH:mm".
function localDatetimeMin() {
	const d = new Date(Date.now() + 60 * 1000);
	const pad = n => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Reveal the custom date / number inputs only when their option is selected.
function wireConditionalOptions() {
	const expirySel = $('#opt-expiry');
	const expiryCustom = $('#opt-expiry-custom');
	expirySel.addEventListener('change', () => {
		const on = expirySel.value === 'custom';
		expiryCustom.classList.toggle('rl-hidden', !on);
		if (on) {
			expiryCustom.min = localDatetimeMin();
			expiryCustom.focus();
		}
	});
	const limitSel = $('#opt-limit');
	const limitNum = $('#opt-limit-num');
	limitSel.addEventListener('change', () => {
		const on = limitSel.value === 'custom';
		limitNum.classList.toggle('rl-hidden', !on);
		if (on) limitNum.focus();
	});
}

// ---- Live validation (custom link + password confirmation) -----------------
function slugValid() {
	const v = $('#opt-slug').value;
	return v === '' || SLUG_RE.test(v);
}

function passwordsMatch() {
	const pw = $('#opt-password').value;
	return !pw || pw === $('#opt-password-confirm').value;
}

function refreshUploadBtn() {
	uploadBtn.disabled = uploading || !selected.length || !slugValid() || !passwordsMatch();
}

// Strip characters that can never be in a slug as the user types, then reflect
// the validity inline so an invalid custom link can never be submitted.
function refreshSlug() {
	const input = $('#opt-slug');
	const affix = $('#opt-slug-affix');
	const help = $('#opt-slug-help');
	const cleaned = input.value.replace(SLUG_BAD_CHARS, '');
	if (cleaned !== input.value) input.value = cleaned;
	const v = input.value;
	if (v === '') {
		affix.classList.remove('rl-input-invalid');
		help.className = 'rl-help';
		help.textContent = 'Letters, numbers, - and _. Blank for a random link.';
	} else if (v.length < 3) {
		affix.classList.add('rl-input-invalid');
		help.className = 'rl-help rl-text-danger';
		help.textContent = 'Use at least 3 characters.';
	} else {
		affix.classList.remove('rl-input-invalid');
		help.className = 'rl-help rl-text-success';
		help.textContent = `Your link: /${v}`;
	}
	refreshUploadBtn();
}

// Reveal the confirm field once a password is typed and reflect whether the two
// entries match.
function refreshPasswordConfirm() {
	const pw = $('#opt-password').value;
	const field = $('#opt-password-confirm-field');
	const confirm = $('#opt-password-confirm');
	const help = $('#opt-password-confirm-help');
	field.classList.toggle('rl-hidden', pw.length === 0);
	if (pw.length === 0) {
		confirm.classList.remove('rl-input-invalid');
		refreshUploadBtn();
		return;
	}
	const c = confirm.value;
	if (c.length === 0) {
		confirm.classList.remove('rl-input-invalid');
		help.className = 'rl-help';
		help.textContent = 'Re-enter the password to confirm.';
	} else if (c !== pw) {
		confirm.classList.add('rl-input-invalid');
		help.className = 'rl-help rl-text-danger';
		help.textContent = 'Passwords do not match.';
	} else {
		confirm.classList.remove('rl-input-invalid');
		help.className = 'rl-help rl-text-success';
		help.textContent = 'Passwords match.';
	}
	refreshUploadBtn();
}

function wireValidation() {
	$('#opt-slug').addEventListener('input', refreshSlug);
	$('#opt-password').addEventListener('input', refreshPasswordConfirm);
	$('#opt-password-confirm').addEventListener('input', refreshPasswordConfirm);
}

async function uploadFile(id, token, file, chunkSize, onProgress, name) {
	const mime = file.type || 'application/octet-stream';
	const reg = await api.post(`/api/shares/${id}/files`, { name: name || file.name, size: file.size, mime }, { headers: { 'X-Edit-Token': token } });
	const fileId = reg.fileId;
	let received = typeof reg.received === 'number' ? reg.received : 0;
	onProgress(received, file.size);

	const headers = { 'X-Edit-Token': token, 'Content-Type': 'application/octet-stream' };

	// Zero-byte file: a single empty chunk completes it.
	if (file.size === 0) {
		await api.raw('PATCH', `/api/shares/${id}/files/${fileId}?offset=0`, new Blob([]), { headers });
		onProgress(0, 0);
		return;
	}

	let guard = 0;
	const maxGuard = Math.ceil(file.size / chunkSize) * 4 + 16;
	// Track attempts/failures per offset so backoff grows across retry rounds and
	// a persistent (non-409) error at the same offset trips a hard stop well
	// before maxGuard - a real 409 resync always resets both counters.
	let lastOffset = -1;
	let attemptsForOffset = 0;
	let failuresForOffset = 0;
	while (received < file.size) {
		if (guard++ > maxGuard) throw new Error('Upload stalled, please retry');
		const offset = received;
		if (offset !== lastOffset) {
			lastOffset = offset;
			attemptsForOffset = 0;
			failuresForOffset = 0;
		}
		const end = Math.min(offset + chunkSize, file.size);
		const blob = file.slice(offset, end);
		let handled = false;
		for (let attempt = 0; attempt < MAX_CHUNK_RETRIES && !handled; attempt++) {
			// Back off before every retry (never before a chunk's first attempt,
			// never after a success) - this also covers the outer while re-attempting
			// a chunk that just exhausted a round of inner retries.
			if (attemptsForOffset > 0) await sleep(backoff(attemptsForOffset - 1));
			attemptsForOffset++;
			try {
				const r = await api.raw('PATCH', `/api/shares/${id}/files/${fileId}?offset=${offset}`, blob, { headers });
				received = typeof r.received === 'number' ? r.received : end;
				onProgress(received, file.size);
				handled = true;
			} catch (e) {
				if (e instanceof ApiError && e.status === 404) {
					throw new Error('Upload failed: this share no longer exists (it may have expired or been deleted).');
				}
				// Server told us the real offset: resync and move on - a normal
				// resume signal, not a failure.
				if (e instanceof ApiError && e.status === 409 && e.data && typeof e.data.received === 'number') {
					received = e.data.received;
					onProgress(received, file.size);
					handled = true;
					break;
				}
				failuresForOffset++;
				if (failuresForOffset >= MAX_OFFSET_FAILURES) {
					throw new Error('Upload failed after repeated errors - the server may be out of space or unreachable. Your progress is saved; try again later.');
				}
				if (attempt === MAX_CHUNK_RETRIES - 1) {
					// Final failure for this round: ask the server where it is and resume.
					try {
						const st = await api.get(`/api/shares/${id}/files/${fileId}/status`, { headers: { 'X-Edit-Token': token } });
						if (typeof st.received === 'number') {
							received = st.received;
							onProgress(received, file.size);
						}
					} catch (e2) {
						if (e2 instanceof ApiError && e2.status === 404) {
							throw new Error('Upload failed: this share no longer exists (it may have expired or been deleted).');
						}
						/* keep the previous offset and let the guard/failure count catch a stall */
					}
				}
			}
		}
	}
	return fileId;
}

// End-to-end upload: encrypt each chunk in the browser before sending. The server
// receives only ciphertext; the filename/mime/chunk-size are encrypted into the
// stored `name`. `onProgress` reports ciphertext bytes.
async function uploadFileE2E(id, token, file, key, chunkSize, onProgress, name) {
	const recordSize = chunkSize + ENC_OVERHEAD;
	const plainSize = file.size;
	const numChunks = Math.max(1, Math.ceil(plainSize / chunkSize));
	const cipherSize = plainSize + numChunks * ENC_OVERHEAD;

	// Encrypted metadata: real name (incl. folder path), mime, and the plaintext
	// chunk size so the recipient can frame the records for decryption.
	const meta = await encryptString(key, JSON.stringify({ name: name || file.name, mime: file.type || 'application/octet-stream', cs: chunkSize }));
	const reg = await api.post(`/api/shares/${id}/files`, { name: meta, size: cipherSize, mime: 'application/octet-stream' }, { headers: { 'X-Edit-Token': token } });
	const fileId = reg.fileId;
	const headers = { 'X-Edit-Token': token, 'Content-Type': 'application/octet-stream' };

	let cipherOff = 0;
	onProgress(0, cipherSize);
	let guard = 0;
	const maxGuard = numChunks * 4 + 16;
	// Track attempts/failures per offset so backoff grows across retry rounds and
	// a persistent (non-409) error at the same offset trips a hard stop well
	// before maxGuard - a real 409 resync always resets both counters.
	let lastOffset = -1;
	let attemptsForOffset = 0;
	let failuresForOffset = 0;
	while (cipherOff < cipherSize) {
		if (guard++ > maxGuard) throw new Error('Upload stalled, please retry');
		if (cipherOff !== lastOffset) {
			lastOffset = cipherOff;
			attemptsForOffset = 0;
			failuresForOffset = 0;
		}
		const chunkIndex = Math.floor(cipherOff / recordSize);
		const plainOff = chunkIndex * chunkSize;
		const end = Math.min(plainOff + chunkSize, plainSize);
		const plainChunk = new Uint8Array(await file.slice(plainOff, end).arrayBuffer());
		const record = await encryptBytes(key, plainChunk);
		let handled = false;
		for (let attempt = 0; attempt < MAX_CHUNK_RETRIES && !handled; attempt++) {
			// Back off before every retry (never before a chunk's first attempt,
			// never after a success) - this also covers the outer while re-attempting
			// a chunk that just exhausted a round of inner retries.
			if (attemptsForOffset > 0) await sleep(backoff(attemptsForOffset - 1));
			attemptsForOffset++;
			try {
				const r = await api.raw('PATCH', `/api/shares/${id}/files/${fileId}?offset=${cipherOff}`, new Blob([record]), { headers });
				cipherOff = typeof r.received === 'number' ? r.received : cipherOff + record.length;
				handled = true;
			} catch (e) {
				if (e instanceof ApiError && e.status === 404) {
					throw new Error('Upload failed: this share no longer exists (it may have expired or been deleted).');
				}
				// Resync to the server's offset (a record boundary) and re-encrypt -
				// a normal resume signal, not a failure.
				if (e instanceof ApiError && e.status === 409 && e.data && typeof e.data.received === 'number') {
					cipherOff = e.data.received;
					handled = true;
					break;
				}
				failuresForOffset++;
				if (failuresForOffset >= MAX_OFFSET_FAILURES) {
					throw new Error('Upload failed after repeated errors - the server may be out of space or unreachable. Your progress is saved; try again later.');
				}
				if (attempt === MAX_CHUNK_RETRIES - 1) {
					// Final failure for this round: ask the server where it is and resume.
					try {
						const st = await api.get(`/api/shares/${id}/files/${fileId}/status`, { headers: { 'X-Edit-Token': token } });
						if (typeof st.received === 'number') cipherOff = st.received;
					} catch (e2) {
						if (e2 instanceof ApiError && e2.status === 404) {
							throw new Error('Upload failed: this share no longer exists (it may have expired or been deleted).');
						}
						/* keep the previous offset and let the guard/failure count catch a stall */
					}
				}
			}
		}
		onProgress(cipherOff, cipherSize);
	}
	return fileId;
}

function shareUrlFor(id, finalizeUrl) {
	if (finalizeUrl) return finalizeUrl;
	const base = (config && config.baseUrl) || location.origin;
	return `${base.replace(/\/$/, '')}/s/${id}`;
}

async function showResult(id, url, e2e) {
	resultEl.textContent = '';

	// The link sits in a mono "copy field" with a primary Copy button on the end.
	const urlText = el('div', { class: 'rl-copyfield-url', title: url }, url);
	const copyBtn = el('button', { class: 'rl-btn rl-btn-primary', onClick: () => copyText(url) }, 'Copy');
	const copyField = el('div', { class: 'rl-copyfield' }, urlText, copyBtn);

	// QR on a white frame so a phone camera reads it against the dark theme.
	const qrFrame = el('div', { class: 'rl-qr-frame' });
	try {
		const { makeQrSvg } = await import('/js/qrcode.js');
		qrFrame.innerHTML = makeQrSvg(url, { border: 1 });
	} catch (e) {
		/* no QR - just omit it below */
	}

	resultEl.append(
		el('div', { class: 'rl-result' },
			el('div', { class: 'rl-result-check', 'aria-hidden': 'true' }, '✓'),
			el('h1', { class: 'rl-h1', style: 'margin:0' }, 'Your share is live'),
			el('p', { class: 'rl-muted', style: 'margin:0;max-width:46ch' },
				e2e
					? 'Only this link can open the files - it carries the decryption key. Save it now; it cannot be recovered if lost.'
					: 'Anyone with this link can view and download the files. Save it somewhere safe.'),
			e2e ? el('span', { class: 'rl-badge rl-badge-gold' }, 'End-to-end encrypted') : null,
			copyField,
			qrFrame.innerHTML ? qrFrame : null,
			qrFrame.innerHTML ? el('p', { class: 'rl-help', style: 'margin:0' }, 'Scan the code to open it on your phone.') : null,
			el('div', { class: 'rl-row rl-row-wrap', style: 'justify-content:center;margin-top:var(--rl-space-2)' },
				el('a', { class: 'rl-btn rl-btn-primary rl-btn-lg', href: url, target: '_blank', rel: 'noopener' }, 'Open share'),
				el('button', { class: 'rl-btn rl-btn-ghost', onClick: resetForm }, 'Share more files'),
			),
		),
	);

	// Swap the composer out for the result so only "Your share is live" shows.
	$('#share-form').classList.add('rl-hidden');
	resultEl.classList.remove('rl-hidden');
	window.scrollTo({ top: 0, behavior: 'smooth' });
}

function resetForm() {
	selected.length = 0;
	renderFileList();
	// Bring the composer back and clear the result.
	$('#share-form').classList.remove('rl-hidden');
	resultEl.classList.add('rl-hidden');
	resultEl.textContent = '';
	$('#opt-title').value = '';
	$('#opt-slug').value = '';
	$('#opt-password').value = '';
	$('#opt-password-confirm').value = '';
	$('#opt-expiry').value = '604800';
	$('#opt-expiry-custom').value = '';
	$('#opt-expiry-custom').classList.add('rl-hidden');
	$('#opt-limit').value = 'unlimited';
	$('#opt-limit-num').value = '';
	$('#opt-limit-num').classList.add('rl-hidden');
	$('#opt-e2e').checked = defaultE2e;
	refreshSlug();
	refreshPasswordConfirm();
	window.scrollTo({ top: 0, behavior: 'smooth' });
}

function setUploading(on) {
	uploading = on;
	resetSpeed();
	refreshUploadBtn();
	uploadBtn.textContent = '';
	if (on) {
		uploadBtn.append(el('span', { class: 'rl-spinner' }), 'Uploading...');
	} else {
		uploadBtn.append('Upload');
	}
	renderFileList();
}

async function doUpload() {
	if (uploading || !selected.length) return;

	// Refresh config for current chunkSize / limits.
	try {
		config = await api.get('/api/config');
	} catch (e) {
		toastErr('Could not reach the server');
		return;
	}

	// Validate options before showing the uploading state so a bad custom date
	// or limit just surfaces a toast.
	let opts;
	try {
		opts = readOptions();
	} catch (e) {
		toastErr(e.message);
		return;
	}

	setUploading(true);
	resultEl.classList.add('rl-hidden');

	let share;
	try {
		share = await api.post('/api/shares', opts);
	} catch (e) {
		setUploading(false);
		if (e instanceof ApiError && e.status === 409) {
			toastErr('That custom link is already taken, pick another');
		} else if (e instanceof ApiError && e.status === 400) {
			toastErr(e.message);
		} else if (e instanceof ApiError && e.status === 403) {
			// Upload session expired (cookie no longer valid): reload to the lock screen.
			toastErr('Upload session expired, returning to the lock screen');
			setTimeout(() => location.reload(), 1200);
		} else if (e instanceof ApiError) {
			// Pass the error object (not just .message) so a 429's retryAfter survives
			// and the toast can show how long until the user can retry.
			toastErr(e);
		} else {
			toastErr('Could not create share');
		}
		return;
	}

	const id = share.id;
	const token = share.editToken;
	const chunkSize = share.chunkSize || (config && config.chunkSize) || 1024 * 1024;
	try {
		localStorage.setItem(EDIT_KEY(id), token);
	} catch (_) {}

	// End-to-end mode: generate the key in the browser. It is never sent to the
	// server - only appended to the final share link (#key).
	let e2eKey = null;
	let e2eKeyB64 = '';
	if (opts.e2e) {
		try {
			const k = await generateKey();
			e2eKey = k.key;
			e2eKeyB64 = k.b64;
		} catch (e) {
			setUploading(false);
			toastErr('This browser does not support end-to-end encryption');
			return;
		}
	}

	let failed = false;
	for (const item of selected) {
		try {
			if (e2eKey) {
				await uploadFileE2E(id, token, item.file, e2eKey, chunkSize, (rec, size) => setProgress(item, Math.round((rec / size) * item.file.size), item.file.size), item.path);
			} else {
				await uploadFile(id, token, item.file, chunkSize, (rec, size) => setProgress(item, rec, size), item.path);
			}
			item.done = true;
			setProgress(item, item.file.size, item.file.size);
		} catch (e) {
			failed = true;
			if (e instanceof ApiError && e.status === 413) {
				toastErr(`"${item.file.name}" is too large for this server`);
			} else if (e instanceof ApiError && e.status === 403) {
				toastErr('Not allowed to upload to this share');
			} else {
				toastErr(`Upload failed for "${item.file.name}"`);
			}
			break;
		}
	}

	if (failed) {
		setUploading(false);
		toast('Some files did not upload. You can retry.', 'error');
		return;
	}

	try {
		const fin = await api.post(`/api/shares/${id}/finalize`, undefined, { headers: { 'X-Edit-Token': token } });
		setUploading(false);
		uploading = false;
		toastOk('Upload complete');
		let url = shareUrlFor(id, fin && fin.url);
		if (e2eKey) url += '#' + e2eKeyB64;
		await showResult(id, url, !!e2eKey);
	} catch (e) {
		setUploading(false);
		toastErr('Could not finalize the share');
	}
}

uploadBtn.addEventListener('click', doUpload);

// ---- Init ------------------------------------------------------------------
wireConditionalOptions();
wireValidation();
loadConfig();
