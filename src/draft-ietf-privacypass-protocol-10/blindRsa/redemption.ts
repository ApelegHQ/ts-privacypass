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

import { autobb } from '../../lib/base64url.js';
import g from '../../lib/global.js';
import timingSafeEqual from '../../lib/timingSafeEqual.js';

const redeemBlindRsaToken = async (
	token: string,
	transientStoreGet: (key: ArrayBuffer) => string | Promise<string>,
	transientStoreDelete: (key: ArrayBuffer) => void | Promise<void>,
) => {
	const rawToken = new Uint8Array(autobb(token));

	/*
	struct {
		uint16_t token_type;
		uint8_t nonce[32];
		uint8_t challenge_digest[32];
		uint8_t token_key_id[Nid]; // Nid = 32
		uint8_t authenticator[Nk]; // Nk = 256
	} Token;
	*/

	const tokenType = (rawToken[0] << 8) | rawToken[1];

	if (tokenType !== 2) {
		return false;
	}

	// Since challenges are already random, we dont need to do anything
	// with the nonce
	// const nonce = rawToken.subarray(2, 2 + 32);
	const challengeDigest = rawToken.subarray(2 + 32, 2 + 32 + 32);

	const tokenKey = await transientStoreGet(challengeDigest);

	if (!tokenKey) {
		return false;
	}

	const tokenKeyId = rawToken.subarray(2 + 32 + 32, 2 + 32 + 32 + 32);
	// assert(tokenKeyId === SHA256(B64TOAB(tokenKey)))
	const rawTokenKey = new Uint8Array(autobb(tokenKey));
	const expectedTokenKeyId = await g.crypto.subtle.digest(
		{ ['name']: 'SHA-256' },
		rawTokenKey,
	);

	if (
		!timingSafeEqual(
			tokenKeyId.buffer.slice(
				tokenKeyId.byteOffset,
				tokenKeyId.byteOffset + tokenKeyId.length,
			),
			expectedTokenKeyId,
		)
	) {
		return false;
	}

	const authenticator = rawToken.subarray(
		2 + 32 + 32 + 32,
		2 + 32 + 32 + 32 + 256,
	);

	const verifiableData = rawToken.subarray(0, 2 + 32 + 32 + 32);

	try {
		// Convert to legacy format for compatibility with Crypto
		const rawVerificationKey = new Uint8Array(
			rawTokenKey.byteLength - 67 + 19,
		);
		rawVerificationKey.set(
			[
				0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
				0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
			],
			0,
		);
		rawVerificationKey.set(rawTokenKey.subarray(67), 19);

		const key = await g.crypto.subtle.importKey(
			'spki',
			rawVerificationKey,
			{
				['name']: 'RSA-PSS',
				['hash']: { ['name']: 'SHA-384' },
			},
			true,
			['verify'],
		);

		const redemptionResult = await g.crypto.subtle.verify(
			{
				['name']: 'RSA-PSS',
				['saltLength']: tokenKey[88] === 'M' ? 0x30 : 0x00,
			},
			key,
			authenticator,
			verifiableData,
		);

		await transientStoreDelete(challengeDigest);

		return redemptionResult;
	} catch {
		return false;
	}
};

const redeemPatAuthorizationHeader = async (
	httpAuthorization: string,
	transientStoreGet: (key: ArrayBuffer) => string | Promise<string>,
	transientStoreDelete: (key: ArrayBuffer) => void | Promise<void>,
): Promise<boolean> => {
	const token = (httpAuthorization.match(
		/^[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Tt][Oo][Kk][Ee][Nn] token=("?)(AA[IJKL][a-zA-Z0-9_-]{469})\1$/i,
	) ?? ([] as never[]))[2];

	if (!token) {
		return false;
	}

	return redeemBlindRsaToken(token, transientStoreGet, transientStoreDelete);
};

export default redeemPatAuthorizationHeader;
export { redeemBlindRsaToken };
