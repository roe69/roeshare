// Minimal streaming ZIP writer (store / no compression). Lets the server hand a
// whole share to the browser as one download without buffering anything in
// memory or shelling out to an external `zip` binary. Uses data descriptors so
// CRCs are emitted after each entry is streamed.
//
// Scope: standard (non-zip64) archive. Suitable for entries and totals under
// 4 GiB, which covers normal share downloads. Callers should fall back to
// individual downloads for anything larger.

const CRC_TABLE = (() => {
	const t = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		t[n] = c >>> 0;
	}
	return t;
})();

function crc32Update(crc, bytes) {
	let c = crc ^ 0xffffffff;
	for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
	return (c ^ 0xffffffff) >>> 0;
}

function dosTime(date) {
	const t = ((date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1)) & 0xffff;
	const d = (((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()) & 0xffff;
	return { t, d };
}

// entries: [{ name: string, file: BunFile (has .stream()), size: number }]
// Returns a ReadableStream<Uint8Array> of the complete archive.
export function createZipStream(entries, when = new Date(0)) {
	const enc = new TextEncoder();
	const { t: time, d: date } = dosTime(when);
	const central = [];
	let offset = 0;

	const push = (controller, bytes) => {
		controller.enqueue(bytes);
		offset += bytes.length;
	};

	return new ReadableStream({
		async start(controller) {
			for (const entry of entries) {
				const nameBytes = enc.encode(entry.name);
				const localOffset = offset;
				const flags = 0x0008; // bit 3: sizes/crc in trailing data descriptor

				// Local file header
				const lh = new DataView(new ArrayBuffer(30));
				lh.setUint32(0, 0x04034b50, true);
				lh.setUint16(4, 20, true); // version needed
				lh.setUint16(6, flags, true);
				lh.setUint16(8, 0, true); // method 0 = store
				lh.setUint16(10, time, true);
				lh.setUint16(12, date, true);
				lh.setUint32(14, 0, true); // crc (in descriptor)
				lh.setUint32(18, 0, true); // compressed size (in descriptor)
				lh.setUint32(22, 0, true); // uncompressed size (in descriptor)
				lh.setUint16(26, nameBytes.length, true);
				lh.setUint16(28, 0, true); // extra length
				push(controller, new Uint8Array(lh.buffer));
				push(controller, nameBytes);

				// File data (streamed), computing CRC + actual size as we go.
				let crc = 0;
				let size = 0;
				const reader = entry.file.stream().getReader();
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					crc = crc32Update(crc, value);
					size += value.length;
					push(controller, value);
				}

				// Data descriptor
				const dd = new DataView(new ArrayBuffer(16));
				dd.setUint32(0, 0x08074b50, true);
				dd.setUint32(4, crc, true);
				dd.setUint32(8, size, true);
				dd.setUint32(12, size, true);
				push(controller, new Uint8Array(dd.buffer));

				central.push({ nameBytes, crc, size, localOffset, time, date, flags });
			}

			// Central directory
			const cdStart = offset;
			for (const e of central) {
				const ch = new DataView(new ArrayBuffer(46));
				ch.setUint32(0, 0x02014b50, true);
				ch.setUint16(4, 20, true); // version made by
				ch.setUint16(6, 20, true); // version needed
				ch.setUint16(8, e.flags, true);
				ch.setUint16(10, 0, true); // method
				ch.setUint16(12, e.time, true);
				ch.setUint16(14, e.date, true);
				ch.setUint32(16, e.crc, true);
				ch.setUint32(20, e.size, true);
				ch.setUint32(24, e.size, true);
				ch.setUint16(28, e.nameBytes.length, true);
				ch.setUint16(30, 0, true); // extra
				ch.setUint16(32, 0, true); // comment
				ch.setUint16(34, 0, true); // disk number
				ch.setUint16(36, 0, true); // internal attrs
				ch.setUint32(38, 0, true); // external attrs
				ch.setUint32(42, e.localOffset, true);
				push(controller, new Uint8Array(ch.buffer));
				push(controller, e.nameBytes);
			}
			const cdSize = offset - cdStart;

			// End of central directory record
			const eocd = new DataView(new ArrayBuffer(22));
			eocd.setUint32(0, 0x06054b50, true);
			eocd.setUint16(4, 0, true);
			eocd.setUint16(6, 0, true);
			eocd.setUint16(8, central.length, true);
			eocd.setUint16(10, central.length, true);
			eocd.setUint32(12, cdSize, true);
			eocd.setUint32(16, cdStart, true);
			eocd.setUint16(20, 0, true);
			push(controller, new Uint8Array(eocd.buffer));

			controller.close();
		},
	});
}
