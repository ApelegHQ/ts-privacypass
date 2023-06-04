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
import { btoau } from '../lib/base64url.js';
import produceTokenChallenge from './challenge.js';

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

const testVectors = [
	[0xff, 'issuer.example', 'origin.example'],
	[0x02, 'issuer.example.com', 'origin.example.net'],
	[0xabba, 'issuer.example.net', ''],
	[0xcafe, 'issuer.example.net', 'anotherorigin.example', new ArrayBuffer(0)],
	[0xcafe, 'issuer.example.net', '', new ArrayBuffer(0)],
	[0x0, 'issuer.example.net', '', new ArrayBuffer(32)],
] as Parameters<typeof produceTokenChallenge>[];

describe('draft-ietf-privacypass-auth-scheme-08/challenge', () => {
	it('Builds correctly formatted challenges', () => {
		testVectors.forEach((v) => {
			const [rawToken, strToken] = produceTokenChallenge(...v);

			assert.equal(strToken, btoau(rawToken));

			const dv = new DataView(rawToken.buffer);

			const expectedIssuerLength = textEncoder.encode(v[1]).byteLength;
			const expectedRedemptionContextLength =
				!v[3] || v[3].byteLength ? 32 : 0;
			const expectedOriginLength = textEncoder.encode(v[2]).byteLength;

			assert.equal(dv.getUint16(0, false), v[0]);
			assert.equal(dv.getUint16(2, false), expectedIssuerLength);
			assert.equal(
				textDecoder.decode(rawToken.slice(4, 4 + expectedIssuerLength)),
				v[1],
			);
			assert.equal(
				dv.getUint8(4 + expectedIssuerLength),
				expectedRedemptionContextLength,
			);
			if (v[3]) {
				assert.deepEqual(
					rawToken.slice(
						4 + expectedIssuerLength + 1,
						4 +
							expectedIssuerLength +
							1 +
							expectedRedemptionContextLength,
					),
					new Uint8Array(v[3]),
				);
			}
			assert.equal(
				dv.getUint16(
					4 +
						expectedIssuerLength +
						1 +
						expectedRedemptionContextLength,
					false,
				),
				expectedOriginLength,
			);
			assert.equal(
				textDecoder.decode(
					rawToken.slice(
						4 +
							expectedIssuerLength +
							1 +
							expectedRedemptionContextLength +
							2,
					),
				),
				v[2],
			);
		});
	});
});
