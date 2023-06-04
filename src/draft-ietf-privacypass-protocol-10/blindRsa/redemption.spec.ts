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
import { autobb, btoau } from '../../lib/base64url.js';
import produceBlindRsaWwwAuthenticateHeader from './challenge.js';
import redeemPatAuthorizationHeader from './redemption.js';

const keygen = async (): Promise<[CryptoKey, Uint8Array]> => {
	const keyPair = await crypto.subtle.generateKey(
		{
			['name']: 'RSA-PSS',
			['modulusLength']: 2048,
			['publicExponent']: new Uint8Array([0x01, 0x00, 0x01]),
			['hash']: { ['name']: 'SHA-384' },
		},
		false,
		['sign', 'verify'],
	);

	const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);

	if (publicKey.byteLength === 294) {
		const prefix = new Uint8Array(294 - 19 + 67);
		prefix.set(
			[
				0x30, 0x82, 0x01, 0x52, 0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86,
				0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0,
				0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
				0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09,
				0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
				0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
				0x02, 0x02, 0xa2, 0x03, 0x02, 0x01, 0x30,
			],
			0,
		);
		prefix.set(new Uint8Array(publicKey.slice(19)), 67);

		return [keyPair.privateKey, prefix];
	}

	return [keyPair.privateKey, new Uint8Array(publicKey)];
};

describe('draft-ietf-privacypass-protocol-10/blindRsa/challenge', () => {
	let tokenKeyS: CryptoKey;
	let tokenKeyP: string;
	let tokenKeyPR: Uint8Array;

	before(async () => {
		const r = await keygen();
		tokenKeyS = r[0];
		tokenKeyPR = r[1];
		tokenKeyP = btoau(r[1]);
	});

	it('Builds correctly formatted challenges', async () => {
		const issuer = 'some-trusted-issuer.example.com';
		const origin = '';

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
										['token-key']: tokenKeyP,
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

		assert.equal(key, tokenKeyP);

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

		const patTokenData = new Uint8Array(2 + 32 + 32 + 32 + 256);

		const patTokenDv = new DataView(patTokenData.buffer);
		patTokenDv.setUint16(0, 2, false);

		const challengeDigest = await globalThis.crypto.subtle.digest(
			{ ['name']: 'SHA-256' },
			challengeData,
		);

		const tokenKeyId = await globalThis.crypto.subtle.digest(
			{ ['name']: 'SHA-256' },
			tokenKeyPR,
		);

		patTokenData.set(new Uint8Array(challengeDigest), 34);
		patTokenData.set(new Uint8Array(tokenKeyId), 66);

		const authenticator = await globalThis.crypto.subtle.sign(
			{
				['name']: 'RSA-PSS',
				['saltLength']: tokenKeyP[88] === 'M' ? 0x30 : 0x00,
			},
			tokenKeyS,
			patTokenData.slice(0, 2 + 32 + 32 + 32),
		);

		patTokenData.set(new Uint8Array(authenticator), 2 + 32 + 32 + 32);

		const token = btoau(patTokenData);

		const redemptionResult = await redeemPatAuthorizationHeader(
			`PrivateToken token="${token}"`,
			() => tokenKeyP,
			() => undefined,
		);

		assert.equal(redemptionResult, true);
	});
});
