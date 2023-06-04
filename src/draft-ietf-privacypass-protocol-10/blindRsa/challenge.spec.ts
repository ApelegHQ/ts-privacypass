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
import { autobb } from '../../lib/base64url.js';
import produceBlindRsaWwwAuthenticateHeader from './challenge.js';

const tokenKey =
	'MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEB' +
	'CDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA2MuQ1cG-VbCpa142x46S' +
	'YEpPAzHFgDP6hckcQechlyllfqRA3v5wV65_lGqbPDs-jK0DTUxsH--iDxvLv3g1' +
	'OQIUBTPKw-TII9n6CfQBCoM-B_B2NkpUAnNxuI_sI8vJcmn8abdTihJkpimMI15I' +
	'eeuuvLoYCtODQte5pjS-GFnvlw4kvMHkTvchpFhYegirBaVjfIAbvSj76iUvgw4k' +
	'i5lGxjSb_edBmNXuz0CrnC6DffGA9Hv_ciD8toTOLYoIwDXP1TUX1J4L59tgrwaL' +
	'uPVsRyu0dHFPrLNiaQZwaas-KBz_HNnf6u4R3ErcnexKfUtJ4d5F1DRU09N03E6W' +
	'nQIDAQAB';

describe('draft-ietf-privacypass-protocol-10/blindRsa/challenge', () => {
	it('Builds correctly formatted challenges', async () => {
		const issuer = 'issuer.example.net';
		const origin = 'origin.example.org';

		const wwwAuthenticateHeader =
			await produceBlindRsaWwwAuthenticateHeader(
				issuer,
				origin,
				() => undefined,
				undefined,
				() =>
					Promise.resolve(
						new Response(
							JSON.stringify({
								['issuer-request-key-uri']: '/origin-token-key',
								['issuer-request-uri']: '/token-request',
								['token-keys']: [
									{
										['token-type']: 0x0000,
										['token-key']: 'anything-goes-0000',
									},
									{
										['token-type']: 0x0002,
										['token-key']: tokenKey,
										['version']: 52,
										['not-before']: Math.floor(
											Date.now() / 1000,
										),
									},
									{
										['token-type']: 0x00ff,
										['token-key']: 'anything-goes-ffff',
									},
								],
							}),
						),
					),
			);

		assert.equal(typeof wwwAuthenticateHeader, 'string');
		const matches = wwwAuthenticateHeader?.match(
			/^[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Tt][Oo][Kk][Ee][Nn] challenge=("?)([A-Za-z0-9_-]+={0,2})\1, *token-key=("?)([A-Za-z0-9_-]+={0,2})\3$/,
		);
		assert.equal(Array.isArray(matches), true);

		const [, , challenge, , key] = matches || [];

		assert.equal(key, tokenKey);

		const challengeData = autobb(challenge);

		const challengeDv = new DataView(challengeData);

		assert.equal(challengeDv.getUint16(0, false), 2);
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
