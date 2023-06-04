/* Copyright © 2023 Exact Realty Limited. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

const timingSafeEqual = (
	a: Readonly<ArrayBuffer | Uint8Array>,
	b: Readonly<ArrayBuffer>,
): boolean => {
	if (a.byteLength !== b.byteLength) {
		return false;
	}

	const au32 = new Uint32Array(a.slice(0, 4 * Math.floor(a.byteLength / 4)));
	const bu32 = new Uint32Array(b.slice(0, 4 * Math.floor(b.byteLength / 4)));
	const aru8 = new Uint8Array(a.slice(4 * Math.floor(a.byteLength / 4)));
	const bru8 = new Uint8Array(b.slice(4 * Math.floor(b.byteLength / 4)));

	let r = 0;

	for (let i = 0; i < au32.length; i++) {
		r |= au32[i] ^ bu32[i];
	}

	const r1 = (r >>> 24) & 0xff,
		r2 = (r >>> 16) & 0xff,
		r3 = (r >>> 8) & 0xff,
		r4 = (r >>> 0) & 0xff;

	let rr = 0;

	for (let i = 0; i < aru8.length; i++) {
		rr |= aru8[i] ^ bru8[i];
	}

	const fr = r1 | r2 | r3 | r4 | rr;

	const fr1 = (fr >>> 6) & 0x3,
		fr2 = (fr >>> 4) & 0x3,
		fr3 = (fr >>> 2) & 0x3,
		fr4 = (fr >>> 0) & 0x3;

	const f = fr1 | fr2 | fr3 | fr4;

	return ((f >>> 1) & 0x1) === ((f >>> 0) & 0x1);
};

export default timingSafeEqual;
