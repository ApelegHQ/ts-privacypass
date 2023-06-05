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
import { autobb, btoau } from '../lib/base64url.js';
import producePowWwwAuthenticateHeader from './challenge.js';
import redeemPatAuthorizationHeader from './redemption.js';

const solver = async (difficulty: number, buffer: Uint8Array) => {
	const proofBuffer = buffer.subarray(2 + 32 + 32);
	globalThis.crypto.getRandomValues(proofBuffer);

	const proofBuffer2 = proofBuffer.subarray(
		0,
		Math.min(Math.ceil(difficulty / 4), proofBuffer.length),
	);

	for (;;) {
		globalThis.crypto.getRandomValues(proofBuffer2);

		const hash = await globalThis.crypto.subtle.digest('SHA-512', buffer);
		const result =
			Array.from(new Uint8Array(hash))
				.slice(0, 8)
				.reduce((acc, cv, i) => {
					const s = difficulty > i * 8 ? 1 << 7 : 0;
					const e =
						!s || difficulty >= (i + 1) * 8
							? 0
							: 1 << (7 - (difficulty % 8));
					let r = 0;
					for (let m = s; m !== e; m >>= 1) r |= cv & m;
					return acc | r;
				}, 0) === 0;

		if (result) {
			return;
		}
	}
};

describe('draft-exact-realty-privacypass-pow/redemption', () => {
	it('Correctly validades and redeems tokens', async () => {
		const issuer = '_difficulty-1._alg-0.pow.privacypass.arpa';
		const origin = 'origin.example.org';

		const wwwAuthenticateHeader = await producePowWwwAuthenticateHeader(
			origin,
			1,
			() => undefined,
			undefined,
		);

		assert.equal(typeof wwwAuthenticateHeader, 'string');
		const matches = wwwAuthenticateHeader?.match(
			/^[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Tt][Oo][Kk][Ee][Nn] challenge=("?)([A-Za-z0-9_-]+={0,2})\1$/,
		);
		assert.equal(Array.isArray(matches), true);

		const [, , challenge] = matches || [];

		const challengeData = autobb(challenge);

		const challengeDv = new DataView(challengeData);

		assert.equal(challengeDv.getUint16(0, false), 22352);
		assert.equal(challengeDv.getUint16(2, false), issuer.length);
		assert.equal(challengeDv.getUint8(4 + issuer.length), 32);
		assert.equal(
			challengeDv.getUint16(4 + issuer.length + 33, false),
			origin.length,
		);
		assert.deepEqual(
			Array.from(
				new Uint8Array(challengeData.slice(4, 4 + issuer.length)),
			),
			issuer.split('').map((c) => c.charCodeAt(0)),
		);
		assert.deepEqual(
			Array.from(
				new Uint8Array(challengeData.slice(4 + issuer.length + 35)),
			),
			origin.split('').map((c) => c.charCodeAt(0)),
		);

		const patTokenData = new Uint8Array(2 + 32 + 32 + 192);

		const patTokenDv = new DataView(patTokenData.buffer);
		patTokenDv.setUint16(0, 22352, false);

		const challengeDigest = await globalThis.crypto.subtle.digest(
			{ ['name']: 'SHA-256' },
			challengeData,
		);

		patTokenData.set(new Uint8Array(challengeDigest), 34);

		await solver(1, patTokenData);

		const token = btoau(patTokenData);

		const redemptionResult = await redeemPatAuthorizationHeader(
			`PrivateToken token="${token}"`,
			() => '1',
			() => undefined,
		);

		assert.equal(redemptionResult, true);
	});
});
