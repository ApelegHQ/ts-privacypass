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

const rsa2048SpkiNewToLegacy = (publicKey: Uint8Array) => {
	const legacyPublicKey = new Uint8Array(342 - 67 + 19);
	legacyPublicKey.set(
		[
			0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
			0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
		],
		0,
	);
	legacyPublicKey.set(publicKey.subarray(67), 19);

	return legacyPublicKey;
};

const rsa2048SpkiLegacyToNew = (publicKey: Uint8Array) => {
	const newPublicKey = new Uint8Array(294 - 19 + 67);
	newPublicKey.set(
		[
			0x30, 0x82, 0x01, 0x52, 0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48,
			0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0, 0x0d, 0x30,
			0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
			0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
			0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa2, 0x03, 0x02, 0x01,
			0x30,
		],
		0,
	);
	newPublicKey.set(new Uint8Array(publicKey.slice(19)), 67);

	return newPublicKey;
};

export { rsa2048SpkiNewToLegacy, rsa2048SpkiLegacyToNew };
