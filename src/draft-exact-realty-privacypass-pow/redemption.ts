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

import { autobb } from '../lib/base64url.js';
import g from '../lib/global.js';

const redeemPowToken = async (
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
		uint8_t token_key_id[Nid]; // Nid = 0
		uint8_t authenticator[Nk]; // Nk = 192
	} Token;
	*/

	const tokenType = (rawToken[0] << 8) | rawToken[1];

	if (tokenType !== 22352) {
		return false;
	}

	// Since challenges are already random, we dont need to do anything
	// with the nonce
	// const nonce = rawToken.subarray(2, 2 + 32);
	const challengeDigest = rawToken.subarray(2 + 32, 2 + 32 + 32);

	let difficulty = Number(await transientStoreGet(challengeDigest));

	if (
		!Number.isSafeInteger(difficulty) ||
		difficulty > 32 ||
		difficulty < 1
	) {
		return false;
	}

	try {
		const digest = new Uint8Array(
			await g.crypto.subtle.digest('SHA-512', rawToken.buffer),
		);

		let i = 0,
			res = 0;

		while (difficulty >= 8) {
			res |= digest[i++];
			difficulty -= 8;
		}

		while (difficulty > 0) {
			res |= digest[i] & (0x01 << (8 - difficulty--));
		}

		const validationResult = (res & 0xff) === 0;

		if (validationResult) {
			await transientStoreDelete(challengeDigest);
		}

		return validationResult;
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
		/^[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Tt][Oo][Kk][Ee][Nn] token=("?)(V1[ABCD][a-zA-Z0-9_-]{341})\1$/i,
	) ?? ([] as never[]))[2];

	if (!token) {
		return false;
	}

	return redeemPowToken(token, transientStoreGet, transientStoreDelete);
};

export default redeemPatAuthorizationHeader;
export { redeemPowToken as redeemPowToken };
