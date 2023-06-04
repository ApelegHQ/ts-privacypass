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
import { autobb } from '../lib/base64url.js';
import producePowWwwAuthenticateHeader from './challenge.js';

describe('draft-ietf-privacypass-protocol-10/blindRsa/challenge', () => {
	it('Builds correctly formatted challenges', async () => {
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
	});
});
