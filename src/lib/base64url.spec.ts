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

import assert from 'node:assert/strict';
import { autob, btoau } from './base64url.js';

const testVectors = [
	['', ''],
	['f', 'Zg=='],
	['fo', 'Zm8='],
	['foo', 'Zm9v'],
	['foob', 'Zm9vYg=='],
	['fooba', 'Zm9vYmE='],
	['foobar', 'Zm9vYmFy'],
	[String.fromCharCode(0x0f, 0xfe, 0xfe), 'D_7-'],
];

describe('base64url', () => {
	it('Encodes strings to base64url', () => {
		testVectors.forEach(([b, au]) => {
			assert.equal(btoau(b), au);
		});
	});

	it('Encodes buffers to base64url', () => {
		testVectors.forEach(([b, au]) => {
			assert.equal(
				btoau(new Uint8Array(b.split('').map((c) => c.charCodeAt(0)))),
				au,
			);
		});
	});

	it('Decodes base64url data strings to strings', () => {
		testVectors.forEach(([b, au]) => {
			assert.equal(autob(au), b);
		});
	});

	it('Decodes base64url data buffers to strings', () => {
		testVectors.forEach(([b, au]) => {
			assert.equal(
				autob(new Uint8Array(au.split('').map((c) => c.charCodeAt(0)))),
				b,
			);
		});
	});
});
